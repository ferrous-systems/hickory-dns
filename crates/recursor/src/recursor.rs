// Copyright 2015-2023 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use async_recursion::async_recursion;
use futures_util::{
    future::{self, select_all},
    stream::{self, BoxStream},
    FutureExt as _, StreamExt, TryFutureExt as _,
};
#[cfg(feature = "dnssec")]
use hickory_proto::xfer::{DnssecDnsHandle, FirstAnswer};
use hickory_proto::{
    error::ProtoError,
    op::{Message, OpCode},
    xfer::{DnsHandle, DnsRequest, DnsRequestOptions, DnsResponse},
};
use hickory_resolver::{
    dns_lru::{DnsLru, TtlConfig},
    name_server::TokioConnectionProvider,
};
use lru_cache::LruCache;
use parking_lot::Mutex;
use tracing::{debug, info, warn};

#[cfg(test)]
use std::str::FromStr;

use crate::{
    proto::{
        op::Query,
        rr::{RData, RecordType},
    },
    recursor_pool::RecursorPool,
    resolver::{
        config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverOpts},
        error::ResolveError,
        lookup::Lookup,
        name_server::{GenericNameServerPool, TokioRuntimeProvider},
        Name,
    },
    Error, ErrorKind,
};

/// Set of nameservers by the zone name
type NameServerCache<P> = LruCache<Name, RecursorPool<P>>;

/// A `Recursor` builder
#[derive(Clone, Copy)]
pub struct RecursorBuilder {
    ns_cache_size: usize,
    record_cache_size: usize,
    #[cfg(feature = "dnssec")]
    security_aware: bool,
    #[cfg(feature = "dnssec")]
    validate: bool,
}

impl Default for RecursorBuilder {
    fn default() -> Self {
        Self {
            ns_cache_size: 1024,
            record_cache_size: 1048576,
            #[cfg(feature = "dnssec")]
            security_aware: false,
            #[cfg(feature = "dnssec")]
            validate: false,
        }
    }
}

impl RecursorBuilder {
    /// Sets the size of the list of cached name servers
    pub fn ns_cache_size(&mut self, size: usize) -> &mut Self {
        self.ns_cache_size = size;
        self
    }

    /// Sets the size of the list of cached records
    pub fn record_cache_size(&mut self, size: usize) -> &mut Self {
        self.record_cache_size = size;
        self
    }

    /// Enables or disables (DNSSEC) security awareness
    #[cfg(feature = "dnssec")]
    pub fn security_aware(&mut self, security_aware: bool) -> &mut Self {
        self.security_aware = security_aware;
        self
    }

    /// Enables or disables validation of DNSSEC records
    #[cfg(feature = "dnssec")]
    pub fn validate(&mut self, validate: bool) -> &mut Self {
        self.validate = validate;
        self
    }

    /// Construct a new recursor using the list of NameServerConfigs for the root node list
    ///
    /// # Panics
    ///
    /// This will panic if the roots are empty.
    pub fn build(&self, roots: impl Into<NameServerConfigGroup>) -> Result<Recursor, ResolveError> {
        #[cfg(not(feature = "dnssec"))]
        let (security_aware, validate) = (false, false);
        #[cfg(feature = "dnssec")]
        let (security_aware, validate) = (self.security_aware, self.validate);

        Recursor::build(
            roots,
            self.ns_cache_size,
            self.record_cache_size,
            security_aware,
            validate,
        )
    }
}

/// A top down recursive resolver which operates off a list of roots for initial recursive requests.
///
/// This is the well known root nodes, referred to as hints in RFCs. See the IANA [Root Servers](https://www.iana.org/domains/root/servers) list.
pub struct Recursor {
    either: RecursorEither,
}

impl Recursor {
    /// Construct the new [`Recursor`] via the [`RecursorBuilder`]
    pub fn builder() -> RecursorBuilder {
        RecursorBuilder::default()
    }

    fn build(
        roots: impl Into<NameServerConfigGroup>,
        ns_cache_size: usize,
        record_cache_size: usize,
        security_aware: bool,
        validate: bool,
    ) -> Result<Self, ResolveError> {
        // configure the hickory-resolver
        let roots: NameServerConfigGroup = roots.into();

        assert!(!roots.is_empty(), "roots must not be empty");

        debug!("Using cache sizes {}/{}", ns_cache_size, record_cache_size);
        let opts = recursor_opts();
        let roots =
            GenericNameServerPool::from_config(roots, opts, TokioConnectionProvider::default());
        let roots = RecursorPool::from(Name::root(), roots);
        let name_server_cache = Arc::new(Mutex::new(NameServerCache::new(ns_cache_size)));
        let record_cache = DnsLru::new(record_cache_size, TtlConfig::default());

        let dns_handle = RecursiveDnsHandle {
            name_server_cache,
            record_cache,
            roots,
            // to validate, the recursor must be security aware
            security_aware: security_aware | validate,
        };

        #[cfg(feature = "dnssec")]
        let either = if validate {
            let record_cache = dns_handle.record_cache.clone();
            let dns_handle = DnssecDnsHandle::new(dns_handle);
            RecursorEither::Validating {
                handle: dns_handle,
                record_cache,
            }
        } else {
            RecursorEither::NonValidating(dns_handle)
        };
        #[cfg(not(feature = "dnssec"))]
        let either = RecursorEither::NonValidating(dns_handle);

        Ok(Self { either })
    }

    pub async fn resolve(
        &self,
        query: Query,
        request_time: Instant,
        query_has_dnssec_ok: bool,
    ) -> Result<Lookup, Error> {
        let mut lookup = match &self.either {
            RecursorEither::NonValidating(handle) => {
                handle.resolve(query.clone(), request_time).await?
            }

            #[cfg(feature = "dnssec")]
            RecursorEither::Validating {
                handle,
                record_cache,
            } => {
                let mut options = DnsRequestOptions::default();
                options.use_edns = true;
                options.edns_set_dnssec_ok = true;
                // FIXME copy-paste of RecursiveDnsHandle::lookup
                let response = handle.lookup(query.clone(), options).first_answer().await?;
                let mut message = response.into_message();

                let records = message
                    .take_answers()
                    .into_iter()
                    .chain(message.take_name_servers())
                    .chain(message.take_additionals());

                // insert records to update Proof field
                let lookup = record_cache.insert_records(query.clone(), records, request_time);
                lookup.ok_or_else(|| Error::from("no records found"))?
            }
        };

        if !query_has_dnssec_ok {
            // RFC 4035 section 3.2.1 if DO bit not set, strip DNSSEC records unless explicitly requested
            let records = lookup
                .records()
                .iter()
                .filter(|rr| {
                    let record_type = rr.record_type();
                    record_type == query.query_type() || !record_type.is_dnssec()
                })
                .cloned()
                .collect();

            lookup = Lookup::new_with_deadline(query, records, lookup.valid_until());
        }

        Ok(lookup)
    }
}

enum RecursorEither {
    NonValidating(RecursiveDnsHandle),
    #[cfg(feature = "dnssec")]
    Validating {
        handle: DnssecDnsHandle<RecursiveDnsHandle>,
        record_cache: DnsLru,
    },
}

/// Non-validating recursive resolver
#[derive(Clone)]
struct RecursiveDnsHandle {
    name_server_cache: Arc<Mutex<NameServerCache<TokioRuntimeProvider>>>,
    record_cache: DnsLru,
    roots: RecursorPool<TokioRuntimeProvider>,
    // whether the DO (DNSSEC OK) bit is set in outgoing queries or not
    security_aware: bool,
}

impl DnsHandle for RecursiveDnsHandle {
    type Response = BoxStream<'static, Result<DnsResponse, ProtoError>>;

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
        let request = request.into();

        let query = if let OpCode::Query = request.op_code() {
            if let Some(query) = request.queries().first().cloned() {
                query
            } else {
                return Box::pin(stream::once(future::err(ProtoError::from(
                    "no query in request",
                ))));
            }
        } else {
            return Box::pin(stream::once(future::err(ProtoError::from(
                "request is not a query",
            ))));
        };

        let this = self.clone();
        stream::once(async move {
            this.resolve(query, Instant::now())
                .map_ok(|lookup| {
                    // HACK `DnssecDnsHandle` will only look at the answer section of the message so
                    // we can put "stubs" in the other fields
                    // XXX this effectively merges the original nameservers and additionals sections
                    // into the answers section
                    let mut msg = Message::new();
                    msg.add_answers(lookup.records().iter().cloned());
                    DnsResponse::new(msg, vec![])
                })
                .map_err(|e| ProtoError::from(e.to_string()))
                .await
        })
        .boxed()
    }
}

impl RecursiveDnsHandle {
    #[async_recursion]
    async fn ns_pool_for_zone(
        &self,
        zone: Name,
        request_time: Instant,
    ) -> Result<RecursorPool<TokioRuntimeProvider>, Error> {
        // TODO: need to check TTLs here.
        if let Some(ns) = self.name_server_cache.lock().get_mut(&zone) {
            return Ok(ns.clone());
        };

        let parent_zone = zone.base_name();

        let nameserver_pool = if parent_zone.is_root() {
            debug!("using roots for {zone} nameservers");
            self.roots.clone()
        } else {
            self.ns_pool_for_zone(parent_zone, request_time).await?
        };

        // TODO: check for cached ns pool for this zone

        let lookup = Query::query(zone.clone(), RecordType::NS);
        let response = self
            .lookup(lookup.clone(), nameserver_pool.clone(), request_time)
            .await?;

        // let zone_nameservers = response.name_servers();
        // let glue = response.additionals();

        // TODO: grab TTL and use for cache
        // get all the NS records and glue
        let mut config_group = NameServerConfigGroup::new();
        let mut need_ips_for_names = Vec::new();

        // unpack all glued records
        for zns in response.record_iter() {
            if let Some(ns_data) = zns.data().as_ns() {
                // let glue_ips = glue
                //     .iter()
                //     .filter(|g| g.name() == ns_data)
                //     .filter_map(Record::data)
                //     .filter_map(RData::to_ip_addr);

                if !is_subzone(zone.base_name().clone(), zns.name().clone()) {
                    warn!(
                        "Dropping out of bailiwick record for {:?} with parent {:?}",
                        zns.name().clone(),
                        zone.base_name().clone()
                    );
                    continue;
                }

                let cached_a = self.record_cache.get(
                    &Query::query(ns_data.0.clone(), RecordType::A),
                    request_time,
                );
                let cached_aaaa = self.record_cache.get(
                    &Query::query(ns_data.0.clone(), RecordType::AAAA),
                    request_time,
                );

                let cached_a = cached_a.and_then(Result::ok).map(Lookup::into_iter);
                let cached_aaaa = cached_aaaa.and_then(Result::ok).map(Lookup::into_iter);

                let glue_ips = cached_a
                    .into_iter()
                    .flatten()
                    .chain(cached_aaaa.into_iter().flatten())
                    .filter_map(|r| RData::ip_addr(&r));

                let mut had_glue = false;
                for ip in glue_ips {
                    let mut udp = NameServerConfig::new(SocketAddr::from((ip, 53)), Protocol::Udp);
                    let mut tcp = NameServerConfig::new(SocketAddr::from((ip, 53)), Protocol::Tcp);

                    udp.trust_negative_responses = true;
                    tcp.trust_negative_responses = true;

                    config_group.push(udp);
                    config_group.push(tcp);
                    had_glue = true;
                }

                if !had_glue {
                    debug!("glue not found for {}", ns_data);
                    need_ips_for_names.push(ns_data);
                }
            }
        }

        // collect missing IP addresses, select over them all, get the addresses
        // make it configurable to query for all records?
        if config_group.is_empty() && !need_ips_for_names.is_empty() {
            debug!("need glue for {}", zone);
            let a_resolves = need_ips_for_names.iter().take(1).map(|name| {
                let a_query = Query::query(name.0.clone(), RecordType::A);
                self.resolve(a_query, request_time).boxed()
            });

            let aaaa_resolves = need_ips_for_names.iter().take(1).map(|name| {
                let aaaa_query = Query::query(name.0.clone(), RecordType::AAAA);
                self.resolve(aaaa_query, request_time).boxed()
            });

            let mut a_resolves: Vec<_> = a_resolves.chain(aaaa_resolves).collect();
            while !a_resolves.is_empty() {
                let (next, _, rest) = select_all(a_resolves).await;
                a_resolves = rest;

                match next {
                    Ok(response) => {
                        debug!("A or AAAA response: {:?}", response);
                        let ips = response.iter().filter_map(RData::ip_addr);

                        for ip in ips {
                            let udp =
                                NameServerConfig::new(SocketAddr::from((ip, 53)), Protocol::Udp);
                            let tcp =
                                NameServerConfig::new(SocketAddr::from((ip, 53)), Protocol::Tcp);

                            config_group.push(udp);
                            config_group.push(tcp);
                        }
                    }
                    Err(e) => {
                        warn!("resolve failed {}", e);
                    }
                }
            }
        }

        // now construct a namesever pool based off the NS and glue records
        let ns = GenericNameServerPool::from_config(
            config_group,
            recursor_opts(),
            TokioConnectionProvider::default(),
        );
        let ns = RecursorPool::from(zone.clone(), ns);

        // store in cache for future usage
        debug!("found nameservers for {}", zone);
        self.name_server_cache.lock().insert(zone, ns.clone());
        Ok(ns)
    }

    async fn resolve(&self, query: Query, request_time: Instant) -> Result<Lookup, Error> {
        if let Some(lookup) = self.record_cache.get(&query, request_time) {
            return lookup.map_err(Into::into);
        }

        // not in cache, let's look for an ns record for lookup
        let zone = match query.query_type() {
            // (RFC4035 section 3.1.4.1) the DS record needs to be queried in the parent zone
            RecordType::NS | RecordType::DS => query.name().base_name(),
            // look for the NS records "inside" the zone
            _ => query.name().clone(),
        };

        let mut zone = zone;
        let mut ns = None;

        // max number of forwarding processes
        'max_forward: for _ in 0..20 {
            match self.ns_pool_for_zone(zone.clone(), request_time).await {
                Ok(found) => {
                    // found the nameserver
                    ns = Some(found);
                    break 'max_forward;
                }
                Err(e) => match e.kind() {
                    ErrorKind::Forward(name) => {
                        // if we already had this name, don't try again
                        if &zone == name {
                            debug!("zone previously searched for {}", name);
                            break 'max_forward;
                        };

                        debug!("ns forwarded to {}", name);
                        zone = name.clone();
                    }
                    _ => return Err(e),
                },
            }
        }

        let ns = ns.ok_or_else(|| Error::from(format!("no nameserver found for {zone}")))?;
        debug!("found zone {} for {}", ns.zone(), query);

        let response = self.lookup(query, ns, request_time).await?;
        Ok(response)
    }

    async fn lookup(
        &self,
        query: Query,
        ns: RecursorPool<TokioRuntimeProvider>,
        now: Instant,
    ) -> Result<Lookup, Error> {
        debug!("lookup: {query} - {}", ns.zone());

        if let Some(lookup) = self.record_cache.get(&query, now) {
            debug!("cached data {lookup:?}");
            return lookup.map_err(Into::into);
        }

        let response = ns.lookup(query.clone(), self.security_aware);

        // TODO: we are only expecting one response
        // TODO: should we change DnsHandle to always be a single response? And build a totally custom handler for other situations?
        // TODO: check if data is "authentic"
        match response.await {
            Ok(r) => {
                let mut r = r.into_message();
                info!("response: {}", r.header());

                let records = r
                    .take_answers()
                    .into_iter()
                    .chain(r.take_name_servers())
                    .chain(r.take_additionals())
                    .filter(|x| {
                        if !is_subzone(ns.zone().clone(), x.name().clone()) {
                            warn!(
                                "Dropping out of bailiwick record {x} for zone {}",
                                ns.zone().clone()
                            );
                            false
                        } else {
                            true
                        }
                    });

                let lookup = self.record_cache.insert_records(query, records, now);

                lookup.ok_or_else(|| Error::from("no records found"))
            }
            Err(e) => {
                warn!("lookup error: {e}");
                Err(Error::from(e))
            }
        }
    }
}

fn recursor_opts() -> ResolverOpts {
    let mut options = ResolverOpts::default();
    options.ndots = 0;
    options.edns0 = true;
    options.validate = false; // we'll need to do any dnssec validation differently in a recursor (top-down rather than bottom-up)
    options.preserve_intermediates = true;
    options.recursion_desired = false;
    options.num_concurrent_reqs = 1;

    options
}

/// Bailiwick/sub zone checking.
///
/// # Overview
///
/// This function checks that two host names have a parent/child relationship, but does so more strictly than elsewhere in the libraries
/// (see implementation notes.)
///
/// A resolver should not return answers outside of its delegated authority -- if we receive a delegation from the root servers for
/// "example.com", that server should only return answers related to example.com or a sub-domain thereof.  Note that record data may point
/// to out-of-bailwick records (e.g., example.com could return a CNAME record for www.example.com that points to example.cdnprovider.net,)
/// but it should not return a record name that is out-of-bailiwick (e.g., we ask for www.example.com and it returns www.otherdomain.com.)
///
/// Out-of-bailiwick responses have been used in cache poisoning attacks.
///
/// ## Examples
///
/// | Parent       | Child                | Expected Result                                                  |
/// |--------------|----------------------|------------------------------------------------------------------|
/// | .            | com.                 | In-bailiwick (true)                                              |
/// | com.         | example.net.         | Out-of-bailiwick (false)                                         |
/// | example.com. | www.example.com.     | In-bailiwick (true)                                              |
/// | example.com. | www.otherdomain.com. | Out-of-bailiwick (false)                                         |
/// | example.com  | www.example.com.     | Out-of-bailiwick (false, note the parent is not fully qualified) |
///
/// # Implementation Notes
///
/// * This function is nominally a wrapper around Name::zone_of, with two additional checks:
/// * If the caller doesn't provide a parent at all, we'll return false.
/// * If the domains have mixed qualification -- that is, if one is fully-qualified and the other partially-qualified, we'll return
///    false.
///
/// # References
///
/// * [RFC 8499](https://datatracker.ietf.org/doc/html/rfc8499) -- DNS Terminology (see page 25)
/// * [The Hitchiker's Guide to DNS Cache Poisoning](https://www.cs.utexas.edu/%7Eshmat/shmat_securecomm10.pdf) -- for a more in-depth
/// discussion of DNS cache poisoning attacks, see section 4, specifically, for a discussion of the Bailiwick rule.
fn is_subzone(parent: Name, child: Name) -> bool {
    if parent.is_empty() {
        return false;
    }

    if (parent.is_fqdn() && !child.is_fqdn()) || (!parent.is_fqdn() && child.is_fqdn()) {
        return false;
    }

    parent.zone_of(&child)
}

#[test]
fn is_subzone_test() {
    assert!(is_subzone(
        Name::from_str(".").unwrap(),
        Name::from_str("com.").unwrap()
    ));
    assert!(is_subzone(
        Name::from_str("com.").unwrap(),
        Name::from_str("example.com.").unwrap()
    ));
    assert!(is_subzone(
        Name::from_str("example.com.").unwrap(),
        Name::from_str("host.example.com.").unwrap()
    ));
    assert!(is_subzone(
        Name::from_str("example.com.").unwrap(),
        Name::from_str("host.multilevel.example.com.").unwrap()
    ));
    assert!(!is_subzone(
        Name::from_str("").unwrap(),
        Name::from_str("example.com.").unwrap()
    ));
    assert!(!is_subzone(
        Name::from_str("com.").unwrap(),
        Name::from_str("example.net.").unwrap()
    ));
    assert!(!is_subzone(
        Name::from_str("example.com.").unwrap(),
        Name::from_str("otherdomain.com.").unwrap()
    ));
    assert!(!is_subzone(
        Name::from_str("com").unwrap(),
        Name::from_str("example.com.").unwrap()
    ));
}
