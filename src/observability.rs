use axum::http::header::HeaderMap;
//use axum_prometheus::metrics::counter;
use opentelemetry::propagation::Extractor;
//use tracing::Event;
//use tracing_subscriber::Layer;

pub struct HeaderExtractor<'a>(pub &'a HeaderMap);

impl<'a> Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

//pub struct TracingEventsCountLayer;
//
//impl<S: tracing::Subscriber> Layer<S> for TracingEventsCountLayer {
//    fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
//        let lvl = event.metadata().level().as_str();
//        let counter = counter!("tracing_events_total", "level" => lvl);
//        counter.increment(1);
//    }
//}
