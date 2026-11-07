// Test Int52 ArithDiv with Arith::Unchecked mode.
// When the result of Int52 division feeds into bitwise operations (like | 0),
// backward propagation clears NodeBytecodeNeedsNaNOrInfinity and NodeBytecodeNeedsNegZero,
// enabling Arith::Unchecked mode which avoids OSR exits on division-by-zero,
// non-exact division, and negative-zero results.

// ===== Basic Int52 div with | 0 (Arith::Unchecked path) =====

function divInt52BitOr(a, b) {
    return (a / b) | 0;
}
noInline(divInt52BitOr);

// Basic Int52 div with | 0 (exact division)
for (let i = 0; i < testLoopCount; i++) {
    let result = divInt52BitOr(2147483648 * 6, 3);
    let expected = (2147483648 * 6 / 3) | 0;
    if (result !== expected)
        throw "FAIL: divInt52BitOr basic, got " + result + " expected " + expected;
}

// Non-exact division: result is truncated by | 0
for (let i = 0; i < testLoopCount; i++) {
    let result = divInt52BitOr(2147483649, 2);
    let expected = (2147483649 / 2) | 0;
    if (result !== expected)
        throw "FAIL: divInt52BitOr non-exact, got " + result + " expected " + expected;
}

// Negative numerator
for (let i = 0; i < testLoopCount; i++) {
    let result = divInt52BitOr(-4503599627370496, 4);
    let expected = (-4503599627370496 / 4) | 0;
    if (result !== expected)
        throw "FAIL: divInt52BitOr negative numerator, got " + result + " expected " + expected;
}

// ===== Division by zero with | 0 (Arith::Unchecked, should NOT OSR exit) =====

function divInt52DivByZeroBitOr(a, b) {
    return (a / b) | 0;
}
noInline(divInt52DivByZeroBitOr);

for (let i = 0; i < testLoopCount; i++) {
    if (i % 2 === 0) {
        let result = divInt52DivByZeroBitOr(2147483648 * 6, 3);
        let expected = (2147483648 * 6 / 3) | 0;
        if (result !== expected)
            throw "FAIL: divInt52DivByZeroBitOr normal case, got " + result;
    } else {
        // x / 0 in JS produces Infinity (or -Infinity), Infinity | 0 = 0.
        // With Arith::Unchecked, chillDiv returns 0 for zero denominator,
        // then | 0 produces 0. Same result.
        let result = divInt52DivByZeroBitOr(2147483648, 0);
        if (result !== 0)
            throw "FAIL: divInt52DivByZeroBitOr div-by-zero, got " + result + " expected 0";
    }
}

// Pure division by zero case
function divInt52AlwaysZeroDivisorBitOr(a) {
    return (a / 0) | 0;
}
noInline(divInt52AlwaysZeroDivisorBitOr);

for (let i = 0; i < testLoopCount; i++) {
    let result = divInt52AlwaysZeroDivisorBitOr(2147483648 + i);
    if (result !== 0)
        throw "FAIL: divInt52AlwaysZeroDivisorBitOr, got " + result + " expected 0";
}

// ===== Negative zero with | 0 (Arith::Unchecked, -0 | 0 = 0) =====

function divInt52NegZeroBitOr(a, b) {
    return (a / b) | 0;
}
noInline(divInt52NegZeroBitOr);

for (let i = 0; i < testLoopCount; i++) {
    // 0 / -2^31 would be -0, but | 0 makes it +0 = 0.
    let result = divInt52NegZeroBitOr(0, -2147483648);
    if (result !== 0)
        throw "FAIL: divInt52NegZeroBitOr, got " + result + " expected 0";
}

// ===== Int52 div with other bitwise operators (also Arith::Unchecked) =====

function divInt52BitAnd(a, b) {
    return (a / b) & 0x7FFFFFFF;
}
noInline(divInt52BitAnd);

for (let i = 0; i < testLoopCount; i++) {
    let result = divInt52BitAnd(4503599627370496, 4);
    let expected = (4503599627370496 / 4) & 0x7FFFFFFF;
    if (result !== expected)
        throw "FAIL: divInt52BitAnd, got " + result + " expected " + expected;
}

function divInt52BitXor(a, b) {
    return (a / b) ^ 0;
}
noInline(divInt52BitXor);

for (let i = 0; i < testLoopCount; i++) {
    let result = divInt52BitXor(2147483648 * 6, 3);
    let expected = (2147483648 * 6 / 3) ^ 0;
    if (result !== expected)
        throw "FAIL: divInt52BitXor, got " + result + " expected " + expected;
}

function divInt52BitShift(a, b) {
    return (a / b) >> 0;
}
noInline(divInt52BitShift);

for (let i = 0; i < testLoopCount; i++) {
    let result = divInt52BitShift(4503599627370496, 2097152);
    let expected = (4503599627370496 / 2097152) >> 0;
    if (result !== expected)
        throw "FAIL: divInt52BitShift, got " + result + " expected " + expected;
}

// ===== Varying inputs to prevent constant folding =====

function divInt52VaryingBitOr(a, b) {
    return (a / b) | 0;
}
noInline(divInt52VaryingBitOr);

for (let i = 0; i < testLoopCount; i++) {
    let a = (2147483648 + i) * 7;
    let b = 7;
    let result = divInt52VaryingBitOr(a, b);
    let expected = (a / b) | 0;
    if (result !== expected)
        throw "FAIL: divInt52VaryingBitOr at i=" + i + ", got " + result + " expected " + expected;
}

// Varying inputs with occasional zero divisor
function divInt52VaryingZeroBitOr(a, b) {
    return (a / b) | 0;
}
noInline(divInt52VaryingZeroBitOr);

for (let i = 0; i < testLoopCount; i++) {
    let a = 2147483648 + i;
    // Every 1000th iteration, divisor is 0
    let b = (i % 1000 === 0) ? 0 : 1;
    let result = divInt52VaryingZeroBitOr(a, b);
    let expected = (a / b) | 0;
    if (result !== expected)
        throw "FAIL: divInt52VaryingZeroBitOr at i=" + i + ", got " + result + " expected " + expected;
}

// ===== Stress test: many different Int52 values through Unchecked path =====

function divInt52StressBitOr(a, b) {
    return (a / b) | 0;
}
noInline(divInt52StressBitOr);

let int52Values = [
    2147483648, -2147483649, 4294967296, -4294967296,
    1099511627776, -1099511627776, 4503599627370496, -4503599627370496,
    2251799813685248, -2251799813685248, 8589934592, -8589934592
];

let divisors = [1, -1, 2, -2, 4, -4, 8, 2147483648];

for (let i = 0; i < testLoopCount; i++) {
    let a = int52Values[i % int52Values.length];
    let b = divisors[i % divisors.length];
    let result = divInt52StressBitOr(a, b);
    let expected = (a / b) | 0;
    if (result !== expected)
        throw "FAIL: divInt52StressBitOr a=" + a + " b=" + b + ", got " + result + " expected " + expected;
}
