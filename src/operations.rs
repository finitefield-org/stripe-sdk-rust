#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operation {
    pub id: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    pub request_content_type: Option<&'static str>,
}

include!(concat!(env!("OUT_DIR"), "/operations.rs"));

pub fn all_operations() -> &'static [Operation] {
    &OPERATIONS
}

pub fn find_operation(operation_id: &str) -> Option<&'static Operation> {
    OPERATIONS
        .binary_search_by(|candidate| candidate.id.cmp(operation_id))
        .ok()
        .map(|index| &OPERATIONS[index])
}

#[cfg(test)]
mod tests {
    use super::{all_operations, find_operation};

    #[test]
    fn generated_operations_are_available() {
        assert!(!all_operations().is_empty());
        assert!(find_operation("GetAccount").is_some());
    }
}
