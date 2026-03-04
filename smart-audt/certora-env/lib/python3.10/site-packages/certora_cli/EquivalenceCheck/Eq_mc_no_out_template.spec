// SHARED CODE START

using CONTRACTB as B;

// Contract A (currentContract) state model
ghost mapping(uint => uint) contractAState;
// State of contract A (currentContract) that has been written to already, so we don't track its reads anymore
ghost mapping(uint => bool) killedFlagA;

// Contract B state model
ghost mapping(uint => uint) contractBState;
// State of contract B that has been written to already, so we don't track its reads anymore
ghost mapping(uint => bool) killedFlagB;

// update first-time reads
hook ALL_SLOAD(uint loc) uint value {
   if(executingContract == currentContract && !killedFlagA[loc]) {
       require contractAState[loc] == value;
   } else if(executingContract == B && !killedFlagB[loc]) {
       require contractBState[loc] == value;
   }
}

// update writes
hook ALL_SSTORE(uint loc, uint value) {
   if(executingContract == currentContract) {
      killedFlagA[loc] = true;
   } else if(executingContract == B) {
      killedFlagB[loc] = true;
   }
}

// assume the two contracts have the same state and address
function assume_equivalent_states() {
    // no slot has been read yet
    require forall uint i. !killedFlagA[i];
    require forall uint i. !killedFlagB[i];
    // same state
    require forall uint i. contractAState[i] == contractBState[i];
    // same address
    require currentContract == B;
}

// sets everything but the callee the same in two environments
function e_equivalence(env e1, env e2) {
    require e1.msg.sender == e2.msg.sender;
    require e1.block.timestamp == e2.block.timestamp;
    require e1.msg.value == e2.msg.value;
    require e1.block.number == e2.block.number;
    // require e1.msg.data == e2.msg.data;
}
// SHARED CODE END

// RULES START
rule equivalence_of_revert_conditions()
{
    storage init = lastStorage;
    assume_equivalent_states();
    bool <Fa>_<Ca>_revert;
    bool <Fb>_<Cb>_revert;
    // using this as opposed to generating input parameters is experimental
    env e_<Fa>_<Ca>; calldataarg args;
    env e_<Fb>_<Cb>;
    e_equivalence(e_<Fa>_<Ca>, e_<Fb>_<Cb>);

    <Fa>@withrevert(e_<Fa>_<Ca>, args);
    <Fa>_<Ca>_revert = lastReverted;

    B.<Fb>@withrevert(e_<Fb>_<Cb>, args) at init;
    <Fb>_<Cb>_revert = lastReverted;

    assert(<Fa>_<Ca>_revert == <Fb>_<Cb>_revert);
}
