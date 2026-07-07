#![cfg(target_arch = "wasm32")]

use kinetic_wasm::KineticNode;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_node_instantiation() {
    // Create a mock javascript callback function
    let callback = js_sys::Function::new_no_args("console.log('Callback invoked!');");

    let mut node = KineticNode::new(callback).expect("Should create node");

    // Start the node, which should trigger the callback
    let result = node.start();
    assert!(
        result.is_ok(),
        "Node should start successfully without panicking"
    );
}
