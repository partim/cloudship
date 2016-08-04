
use netmachines::net::openssl::StartTlsServer;
use netmachines::sockets::openssl::StartTlsListener;
use netmachines::sync::TriggerSender;
use netmachines::utils::ResponseExt;
use rotor::{EventSet, GenericScope, Machine, Response, Scope, Void};
use super::config::Config;
use super::protocol::Protocol;
use super::transport::Accept;

pub struct Server<X, P: Protocol>(StartTlsServer<X, Accept<P>>);

impl<X, P: Protocol> Server<X, P> {
    pub fn new<S>(lsnr: StartTlsListener, config: Config, protocol: P,
                  scope: &mut S) -> (Response<Self, Void>, TriggerSender)
               where S: GenericScope {
        let (res, trigger) = StartTlsServer::new(lsnr, Accept::new(config,
                                                                   protocol),
                                                 scope);
        (res.map_self(Server), trigger)
    }
}

impl<X, P: Protocol> Machine for Server<X, P> {
    type Context = X;
    type Seed = <StartTlsServer<X, Accept<P>> as Machine>::Seed;

    fn create(seed: Self::Seed, scope: &mut Scope<Self::Context>)
              -> Response<Self, Void> {
        StartTlsServer::create(seed, scope).map_self(Server)
    }

    fn ready(self, events: EventSet, scope: &mut Scope<Self::Context>)
             -> Response<Self, Self::Seed> {
        self.0.ready(events, scope).map_self(Server)
    }

    fn spawned(self, scope: &mut Scope<Self::Context>)
               -> Response<Self, Self::Seed> {
        self.0.spawned(scope).map_self(Server)
    }

    fn timeout(self, scope: &mut Scope<Self::Context>)
               -> Response<Self, Self::Seed> {
        self.0.timeout(scope).map_self(Server)
    }

    fn wakeup(self, scope: &mut Scope<Self::Context>)
              -> Response<Self, Self::Seed> {
        self.0.wakeup(scope).map_self(Server)
    }
}
