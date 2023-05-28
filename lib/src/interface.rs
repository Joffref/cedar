extern crate alloc;
extern crate core;
extern crate wee_alloc;

use cedar_policy::{PolicySet, Entities, Authorizer, EntityUid, Context, Request, Decision};

use std::{slice};
use std::collections::HashMap;
use std::str::FromStr;

use once_cell::sync::Lazy;

static mut ENGINE: Lazy<CedarEngine>= Lazy::new(|| {
    CedarEngine {
        entity_store: Entities::empty(),
        policy_set: PolicySet::new(),
        authorizer: Authorizer::new(),
    }
});

static mut HEAP: Lazy<HashMap<* mut u8, &mut [u8]>> = Lazy::new(|| {
    HashMap::new()
});

struct CedarEngine {
    entity_store: Entities,
    policy_set: PolicySet,
    authorizer: Authorizer
}

impl CedarEngine {
    fn set_entities(&mut self, entities_json: &str) {
        match Entities::from_json_str(entities_json, None) {
            Ok(entities) => {
                self.entity_store = entities;
            }
            Err(e) => {
                println!("Error adding entity: {}", e);
            }
        }
    }
    fn set_policies(&mut self, policies_str: &str) {
        match PolicySet::from_str(policies_str) {
            Ok(policies) => {
                self.policy_set = policies;
            }
            Err(e) => {
                println!("Error adding policy: {}", e);
            }
        }
    }
    fn is_authorized(&self, entity: &str, action: &str, resource: &str, context: &str) -> String  {
        let principal = EntityUid::from_str(entity).expect("entity parse error");
        let action = EntityUid::from_str(action).expect("entity parse error");
        let resource = EntityUid::from_str(resource).expect("entity parse error");
        let context = Context::from_json_str(context, None).unwrap();
        let query = Request::new(Some(principal), Some(action), Some(resource), context);
        let response = self.authorizer.is_authorized(&query, &self.policy_set, &self.entity_store);
        return if response.decision() == Decision::Allow {
            String::from("Allow")
        } else {
            String::from("Deny")
        }
    }
}

#[cfg_attr(all(target_arch = "wasm32"), export_name = "set_entities")]
#[no_mangle]
pub unsafe extern "C" fn _set_entities(entities_ptr: u32, entities_len: u32) {
    let entities = ptr_to_string(entities_ptr, entities_len);
    ENGINE.set_entities(&entities);
}

#[cfg_attr(all(target_arch = "wasm32"), export_name = "set_policies")]
#[no_mangle]
pub unsafe extern "C" fn _set_policies(policies_ptr: u32, policies_len: u32) {
    let policies = ptr_to_string(policies_ptr, policies_len);
    ENGINE.set_policies(&policies);
}


#[cfg_attr(all(target_arch = "wasm32"), export_name = "is_authorized")]
#[no_mangle]
pub unsafe extern "C" fn _is_authorized(
    entity_ptr: u32,
    entity_len: u32,
    action_ptr: u32,
    action_len: u32,
    resource_ptr: u32,
    resource_len: u32,
    context_ptr: u32,
    context_len: u32,
) -> u64 {
    let entity = ptr_to_string(entity_ptr, entity_len);
    let action = ptr_to_string(action_ptr, action_len);
    let resource = ptr_to_string(resource_ptr, resource_len);
    let context = ptr_to_string(context_ptr, context_len);
    let result = ENGINE.is_authorized(entity.as_str(), action.as_str(), resource.as_str(), context.as_str());
    let (ptr, len) = string_to_ptr(&result);
    std::mem::forget(result);
    return ((ptr as u64) << 32) | len as u64;
}

/// Returns a string from WebAssembly compatible numeric types representing
/// its pointer and length.
unsafe fn ptr_to_string(ptr: u32, len: u32) -> String {
    let slice = slice::from_raw_parts_mut(ptr as *mut u8, len as usize);
    let utf8 = std::str::from_utf8_unchecked_mut(slice);
    return String::from(utf8);
}

/// Returns a pointer and size pair for the given string in a way compatible
/// with WebAssembly numeric types.
///
/// Note: This doesn't change the ownership of the String. To intentionally
/// leak it, use [`std::mem::forget`] on the input after calling this.
unsafe fn string_to_ptr(s: &String) -> (u32, u32) {
    return (s.as_ptr() as u32, s.len() as u32);
}

/// Set the global allocator to the WebAssembly optimized one.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// WebAssembly export that allocates a pointer (linear memory offset) that can
/// be used for a string.
///
/// This is an ownership transfer, which means the caller must call
/// [`deallocate`] when finished.
#[cfg_attr(all(target_arch = "wasm32"), export_name = "allocate")]
#[no_mangle]
pub unsafe extern "C" fn _allocate(size: u32) -> * mut u8 {
   allocate(size as usize)
}

/// Allocates size bytes and leaks the pointer where they start.
unsafe fn allocate(size: usize) -> *mut u8 {
    // Allocate the amount of bytes needed.
    let vec: Vec<u8> = Vec::with_capacity(size);

    // into_raw leaks the memory to the caller.
    let  ptr = vec.as_ptr() as *mut u8;

    // Store the boxed_vec to prevent it from being deallocated.
    HEAP.insert(ptr, vec.leak());
    // Return the pointer to the caller.
    ptr
}


/// WebAssembly export that deallocates a pointer of the given size (linear
/// memory offset, byteCount) allocated by [`allocate`].
#[cfg_attr(all(target_arch = "wasm32"), export_name = "deallocate")]
#[no_mangle]
pub unsafe extern "C" fn _deallocate(ptr: u32, size: u32) {
    deallocate(ptr as *mut u8, size as usize);
}

/// Retakes the pointer which allows its memory to be freed.
unsafe fn deallocate(ptr: *mut u8, size: usize) {
    // Remove the boxed_vec from the map so it can be deallocated.
    HEAP.remove(&ptr).expect("Pointer not found in heap map");
    let _ = Vec::from_raw_parts(ptr, size, size);
    let _ = *ptr; // explicitly drop the pointer
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn set_policies() {
        let mut engine = CedarEngine{
            authorizer: Authorizer::new(),
            entity_store: Entities::empty(),
            policy_set: PolicySet::new(),
        };
        let policies = "permit(principal, action, resource); permit(principal, action, resource);";
        engine.set_policies(policies);
        let mut counter = 0;
        for _policy in engine.policy_set.policies() {
            counter += 1;
        }
        assert_eq!(counter, 2);
    }
    #[test]
    fn set_entities() {
        let mut engine = CedarEngine{
            authorizer: Authorizer::new(),
            entity_store: Entities::empty(),
            policy_set: PolicySet::new(),
        };
        let entities_json = r#"[
            {
                "uid": {
                    "type": "User",
                    "id": "Bob"
                },
                "attrs": {},
                "parents": [
                    {
                        "type": "Role",
                        "id": "vacationPhotoJudges"
                    },
                    {
                        "type": "Role",
                        "id": "juniorPhotographerJudges"
                    }
                ]
            },
            {
                "uid": {
                    "type": "Role",
                    "id": "vacationPhotoJudges"
                },
                "attrs": {},
                "parents": []
            },
            {
                "uid": {
                    "type": "Role",
                    "id": "juniorPhotographerJudges"
                },
                "attrs": {},
                "parents": []
            }
        ]"#;
        engine.set_entities(entities_json);
        let mut counter = 0;
        for _entity in engine.entity_store.iter() {
            counter += 1;
        }
        assert_eq!(counter, 3);
    }

    #[test]
    fn evaluate() {
        let mut engine = CedarEngine{
            authorizer: Authorizer::new(),
            entity_store: Entities::empty(),
            policy_set: PolicySet::new(),
        };
        let policies = "permit(principal, action, resource); permit(principal, action, resource);";
        engine.set_policies(policies);
        let entities = "[]";
        engine.set_entities(entities);
        let result = engine.is_authorized("User::\"alice\"", "Action::\"update\"", "Photo::\"VacationPhoto94.jpg\"", "{}");
        assert_eq!(result, "Allow");
    }

    #[test]
     fn allocate_deallocate() {
        unsafe {
            let ptr = allocate(10);
            assert_eq!(HEAP.contains_key(&ptr), true);
            deallocate(ptr, 10);
            assert_eq!(HEAP.contains_key(&ptr), false);
            let ptr = allocate(10);
            assert_eq!(HEAP.contains_key(&ptr), true);
            let ptr2 = allocate(10);
            assert_eq!(HEAP.contains_key(&ptr), true);
            assert_ne!(ptr as u8, ptr2 as u8);
            assert_eq!(HEAP.len(), 2);
            deallocate(ptr, 10);
            assert_eq!(HEAP.contains_key(&ptr), false);
            assert_eq!(HEAP.len(), 1);
            deallocate(ptr2, 10);
            assert_eq!(HEAP.contains_key(&ptr2), false);
            assert_eq!(HEAP.len(), 0);
        }
    }
}
