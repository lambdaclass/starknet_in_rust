%lang starknet
%builtins keccak range_check
from starkware.cairo.common.cairo_builtins import KeccakBuiltin
from starkware.cairo.common.keccak_state import KeccakBuiltinState
from starkware.cairo.common.alloc import alloc

func simple_keccak{keccak_ptr: KeccakBuiltin*}(value: felt) -> (res: felt) {
    assert keccak_ptr[0].input = KeccakBuiltinState(value, 2, 3, 4, 5, 6, 7, 8);
    let result = keccak_ptr[0].output;
    let keccak_ptr = keccak_ptr + KeccakBuiltin.SIZE;
    assert result.s0 = 528644516554364142278482415480021626364691973678134577961206;
    assert result.s1 = 768681319646568210457759892191562701823009052229295869963057;
    assert result.s2 = 1439835513376369408063324968379272676079109225238241190228026;
    assert result.s3 = 1150396629165612276474514703759718478742374517669870754478270;
    assert result.s4 = 1515147102575186161827863034255579930572231617017100845406254;
    assert result.s5 = 1412568161597072838250338588041800080889949791225997426843744;
    assert result.s6 = 982235455376248641031519404605670648838699214888770304613539;
    assert result.s7 = 1339947803093378278438908448344904300127577306141693325151040;

    return (res=result.s0);
}

@view
func get_balance{}(value: felt) -> (res: felt) {
    alloc_locals;
    let (local keccak_ptr: KeccakBuiltin*) = alloc();
    let (res) = simple_keccak{keccak_ptr=keccak_ptr}(value);
    return (res=0);
}
