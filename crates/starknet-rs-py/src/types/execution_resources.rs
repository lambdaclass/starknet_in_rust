use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use pyo3::prelude::*;
use std::collections::HashMap;

#[pyclass]
#[pyo3(name = "ExecutionResources")]
#[derive(Debug)]
pub struct PyExecutionResources {
    inner: ExecutionResources,
}

#[pymethods]
impl PyExecutionResources {
    #[getter]
    fn n_steps(&self) -> usize {
        self.inner.n_steps
    }

    #[getter]
    fn builtin_instance_counter(&self) -> HashMap<String, usize> {
        self.inner.builtin_instance_counter.clone()
    }

    #[getter]
    fn n_memory_holes(&self) -> usize {
        self.inner.n_memory_holes
    }
}

impl From<ExecutionResources> for PyExecutionResources {
    fn from(inner: ExecutionResources) -> Self {
        Self { inner }
    }
}
