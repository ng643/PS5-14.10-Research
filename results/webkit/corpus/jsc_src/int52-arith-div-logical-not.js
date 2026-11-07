// Test that LogicalNot does NOT incorrectly clear NodeBytecodeNeedsNaNOrInfinity
// for ArithDiv. Division by zero produces ±Infinity, and !Infinity is false.
// If the flag were incorrectly cleared, chillDiv would return 0 for zero-divisor,
// and !0 would be true — a wrong result.

// ===== Basic: !(int52 / 0) should be false (Infinity is truthy) =====

function divInt52LogicalNotDivByZero(a, b) {
    return !(a / b);
}
noInline(divInt52LogicalNotDivByZero);

// Warm up with normal division first so the function gets JIT-compiled
for (let i = 0; i < testLoopCount; i++) {
    let result = divInt52LogicalNotDivByZero(2147483648 * 6, 3);
    if (result !== false)
        throw "FAIL: divInt52LogicalNotDivByZero normal, got " + result + " expected false";
}

// Now test division by zero: x / 0 = Infinity, !Infinity = false
for (let i = 0; i < testLoopCount; i++) {
    let result = divInt52LogicalNotDivByZero(2147483648, 0);
    // !Infinity should be false. If the optimization incorrectly clears
    // NeedsNaNOrInfinity, chillDiv returns 0, and !0 = true (WRONG).
    if (result !== false)
        throw "FAIL: divInt52LogicalNotDivByZero div-by-zero, got " + result + " expected false";
}

// ===== Mixed: alternate between normal and div-by-zero =====

function divInt52LogicalNotMixed(a, b) {
    return !(a / b);
}
noInline(divInt52LogicalNotMixed);

for (let i = 0; i < testLoopCount; i++) {
    if (i % 2 === 0) {
        let result = divInt52LogicalNotMixed(2147483648 * 4, 2);
        if (result !== false)
            throw "FAIL: divInt52LogicalNotMixed normal, got " + result + " expected false";
    } else {
        // nonzero / 0 = Infinity, !Infinity = false
        let result = divInt52LogicalNotMixed(2147483648, 0);
        if (result !== false)
            throw "FAIL: divInt52LogicalNotMixed div-by-zero, got " + result + " expected false";
    }
}

// ===== Negative infinity: negative_int52 / 0 = -Infinity, !(-Infinity) = false =====

function divInt52LogicalNotNegInf(a, b) {
    return !(a / b);
}
noInline(divInt52LogicalNotNegInf);

for (let i = 0; i < testLoopCount; i++) {
    if (i % 2 === 0) {
        let result = divInt52LogicalNotNegInf(-2147483648 * 6, 3);
        if (result !== false)
            throw "FAIL: divInt52LogicalNotNegInf normal, got " + result + " expected false";
    } else {
        let result = divInt52LogicalNotNegInf(-2147483648, 0);
        if (result !== false)
            throw "FAIL: divInt52LogicalNotNegInf neg-div-by-zero, got " + result + " expected false";
    }
}

// ===== 0 / 0 = NaN, !NaN = true (this is the NaN case, should still work) =====

function divInt52LogicalNotNaN(a, b) {
    return !(a / b);
}
noInline(divInt52LogicalNotNaN);

for (let i = 0; i < testLoopCount; i++) {
    if (i % 3 === 0) {
        // Normal case: result is nonzero, !nonzero = false
        let result = divInt52LogicalNotNaN(2147483648 * 6, 3);
        if (result !== false)
            throw "FAIL: divInt52LogicalNotNaN normal, got " + result + " expected false";
    } else if (i % 3 === 1) {
        // Infinity case: nonzero / 0 = Infinity, !Infinity = false
        let result = divInt52LogicalNotNaN(2147483648, 0);
        if (result !== false)
            throw "FAIL: divInt52LogicalNotNaN infinity, got " + result + " expected false";
    } else {
        // NaN case: 0 / 0 = NaN, !NaN = true
        let result = divInt52LogicalNotNaN(0, 0);
        if (result !== true)
            throw "FAIL: divInt52LogicalNotNaN nan, got " + result + " expected true";
    }
}

// ===== Exact division producing zero: !(0 / int52) = true for positive divisor =====

function divInt52LogicalNotZeroResult(a, b) {
    return !(a / b);
}
noInline(divInt52LogicalNotZeroResult);

for (let i = 0; i < testLoopCount; i++) {
    // 0 / positive = +0, !(+0) = true
    let result = divInt52LogicalNotZeroResult(0, 2147483648);
    if (result !== true)
        throw "FAIL: divInt52LogicalNotZeroResult zero, got " + result + " expected true";
}

// ===== Verify ArithMod with LogicalNot still works (regression check) =====
// Mod by zero produces NaN, !NaN = true. chillMod returns 0, !0 = true. Same result.

function modInt52LogicalNotDivByZero(a, b) {
    return !(a % b);
}
noInline(modInt52LogicalNotDivByZero);

for (let i = 0; i < testLoopCount; i++) {
    if (i % 2 === 0) {
        let result = modInt52LogicalNotDivByZero(2147483648, 7);
        if (result !== false)
            throw "FAIL: modInt52LogicalNotDivByZero normal, got " + result + " expected false";
    } else {
        // x % 0 = NaN, !NaN = true. chillMod returns 0, !0 = true. Correct.
        let result = modInt52LogicalNotDivByZero(2147483648, 0);
        if (result !== true)
            throw "FAIL: modInt52LogicalNotDivByZero mod-by-zero, got " + result + " expected true";
    }
}
