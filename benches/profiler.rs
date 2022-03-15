use criterion::profiler::Profiler;
use pprof::ProfilerGuard;
use std::{fs::File, os::raw::c_int, path::Path};

pub struct FlameGraphProfiler<'a> {
    frequency: c_int,
    active_profiler: Option<ProfilerGuard<'a>>,
}

impl<'a> FlameGraphProfiler<'a> {
    #[allow(dead_code)]
    pub fn new(frequency: c_int) -> Self {
        FlameGraphProfiler {
            frequency,
            active_profiler: None,
        }
    }
}

impl<'a> Profiler for FlameGraphProfiler<'a> {
    fn start_profiling(&mut self, _benchmark_id: &str, _benchmark_dir: &Path) {
        self.active_profiler = Some(ProfilerGuard::new(self.frequency).unwrap());
    }

    fn stop_profiling(&mut self, _benchmark_id: &str, benchmark_dir: &Path) {
        std::fs::create_dir_all(benchmark_dir).unwrap();
        let flame_graph_path = benchmark_dir.join("flame_graph.svg");
        let flame_graph_file = File::create(&flame_graph_path)
            .expect("File system error while creating flame_graph.svg");
        if let Some(profiler) = self.active_profiler.take() {
            profiler
                .report()
                .build()
                .unwrap()
                .flamegraph(flame_graph_file)
                .expect("Error writing flame graph");
        }
    }
}
