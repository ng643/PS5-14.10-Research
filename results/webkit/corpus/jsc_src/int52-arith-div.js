// Test Int52 division operation with comprehensive edge cases

// ===== Basic Int52 division with exact results =====
function divideInt52(a, b) {
    return a / b;
}
noInline(divideInt52);

// Int52 values (exceed Int32 max of 2147483647)
let large = 2147483648 * 6;  // 2^31 * 6
let expected = large / 3;
for (let i = 0; i < testLoopCount; i++) {
    let result = divideInt52(large, 3);
    if (result !== expected)
        throw "FAIL: int52 div basic case, got " + result + " expected " + expected;
}

// Larger Int52 values
let larger = 4503599627370496;  // 2^52
let largerExpected = larger / 4;
for (let i = 0; i < testLoopCount; i++) {
    let result = divideInt52(larger, 4);
    if (result !== largerExpected)
        throw "FAIL: int52 div large case, got " + result + " expected " + largerExpected;
}

// Negative Int52 numerator
let negative = -2147483648 * 6;
let negExpected = negative / 3;
for (let i = 0; i < testLoopCount; i++) {
    let result = divideInt52(negative, 3);
    if (result !== negExpected)
        throw "FAIL: int52 div negative numerator, got " + result + " expected " + negExpected;
}

// Test with negative divisor
let negDivisorExpected = large / -3;
for (let i = 0; i < testLoopCount; i++) {
    let result = divideInt52(large, -3);
    if (result !== negDivisorExpected)
        throw "FAIL: int52 div negative divisor, got " + result + " expected " + negDivisorExpected;
}

// Test both negative
let bothNegExpected = negative / -3;
for (let i = 0; i < testLoopCount; i++) {
    let result = divideInt52(negative, -3);
    if (result !== bothNegExpected)
        throw "FAIL: int52 div both negative, got " + result + " expected " + bothNegExpected;
}

// ===== AnyIntAsDouble cases =====
function divideAnyIntAsDouble(a, b) {
    return (a * 1.0) / (b * 1.0);
}
noInline(divideAnyIntAsDouble);

let doubleInt52 = 2147483648.0 * 6;  // 2^31 * 6 as double
let doubleExpected = doubleInt52 / 3;
for (let i = 0; i < testLoopCount; i++) {
    let result = divideAnyIntAsDouble(doubleInt52, 3);
    if (result !== doubleExpected)
        throw "FAIL: AnyIntAsDouble div case, got " + result + " expected " + doubleExpected;
}

// ===== Self-division (a / a == 1) =====
function divideSelf(a) {
    return a / a;
}
noInline(divideSelf);

for (let i = 0; i < testLoopCount; i++) {
    let result = divideSelf(2147483648);
    if (result !== 1)
        throw "FAIL: divideSelf(2^31), got " + result + " expected 1";
}

for (let i = 0; i < testLoopCount; i++) {
    let result = divideSelf(-4503599627370496);
    if (result !== 1)
        throw "FAIL: divideSelf(-2^52), got " + result + " expected 1";
}

// ===== Division by 1 and -1 =====
function divByOne(a) {
    return a / 1;
}
noInline(divByOne);

for (let i = 0; i < testLoopCount; i++) {
    let result = divByOne(2147483648);
    if (result !== 2147483648)
        throw "FAIL: divByOne(2^31), got " + result + " expected 2147483648";
}

for (let i = 0; i < testLoopCount; i++) {
    let result = divByOne(-4503599627370496);
    if (result !== -4503599627370496)
        throw "FAIL: divByOne(-2^52), got " + result + " expected -4503599627370496";
}

function divByNegOne(a) {
    return a / -1;
}
noInline(divByNegOne);

for (let i = 0; i < testLoopCount; i++) {
    let result = divByNegOne(2147483648);
    if (result !== -2147483648)
        throw "FAIL: divByNegOne(2^31), got " + result + " expected -2147483648";
}

for (let i = 0; i < testLoopCount; i++) {
    let result = divByNegOne(-4503599627370496);
    if (result !== 4503599627370496)
        throw "FAIL: divByNegOne(-2^52), got " + result + " expected 4503599627370496";
}

// ===== Division by powers of 2 =====
function divByPowerOfTwo(a, b) {
    return a / b;
}
noInline(divByPowerOfTwo);

for (let i = 0; i < testLoopCount; i++) {
    let result = divByPowerOfTwo(1099511627776, 1024);  // 2^40 / 2^10 = 2^30
    if (result !== 1073741824)
        throw "FAIL: divByPowerOfTwo 2^40/2^10, got " + result + " expected 1073741824";
}

for (let i = 0; i < testLoopCount; i++) {
    let result = divByPowerOfTwo(4503599627370496, 2097152);  // 2^52 / 2^21 = 2^31
    if (result !== 2147483648)
        throw "FAIL: divByPowerOfTwo 2^52/2^21, got " + result + " expected 2147483648";
}

// ===== Negative zero edge cases =====
// For division, -0 occurs when numerator == 0 and denominator < 0

function checkNegativeZero(value, testName) {
    if (value !== 0)
        throw "FAIL: " + testName + " should be zero, got " + value;
    if (1 / value !== -Infinity)
        throw "FAIL: " + testName + " should be -0, got " + (1/value);
}

function checkPositiveZero(value, testName) {
    if (value !== 0)
        throw "FAIL: " + testName + " should be zero, got " + value;
    if (1 / value !== Infinity)
        throw "FAIL: " + testName + " should be +0, got " + (1/value);
}

// 0 / negative_int52 = -0
function divNegZero1(a, b) {
    return a / b;
}
noInline(divNegZero1);

for (let i = 0; i < testLoopCount; i++) {
    let result = divNegZero1(0, -2147483648);
    checkNegativeZero(result, "divNegZero1: 0 / -2147483648");
}

function divNegZero2(a, b) {
    return a / b;
}
noInline(divNegZero2);

for (let i = 0; i < testLoopCount; i++) {
    let result = divNegZero2(0, -4503599627370496);
    checkNegativeZero(result, "divNegZero2: 0 / -4503599627370496");
}

// 0 / positive_int52 = +0
function divPosZero1(a, b) {
    return a / b;
}
noInline(divPosZero1);

for (let i = 0; i < testLoopCount; i++) {
    let result = divPosZero1(0, 2147483648);
    checkPositiveZero(result, "divPosZero1: 0 / 2147483648");
}

// ===== Non-exact division (should fall back to double via OSR exit) =====
function divNonExact(a, b) {
    return a / b;
}
noInline(divNonExact);

for (let i = 0; i < testLoopCount; i++) {
    let result = divNonExact(2147483649, 2);  // Not exactly divisible
    if (result !== 2147483649 / 2)
        throw "FAIL: divNonExact, got " + result + " expected " + (2147483649 / 2);
}

// ===== Boundary values =====

// MAX_INT52 / 1 = MAX_INT52
function divMaxInt52(a, b) {
    return a / b;
}
noInline(divMaxInt52);

for (let i = 0; i < testLoopCount; i++) {
    let result = divMaxInt52(2251799813685247, 1);  // MAX_INT52 (2^51-1)
    if (result !== 2251799813685247)
        throw "FAIL: divMaxInt52 / 1, got " + result + " expected 2251799813685247";
}

// MIN_INT52 / 1 = MIN_INT52
function divMinInt52(a, b) {
    return a / b;
}
noInline(divMinInt52);

for (let i = 0; i < testLoopCount; i++) {
    let result = divMinInt52(-2251799813685248, 1);  // MIN_INT52 (-2^51)
    if (result !== -2251799813685248)
        throw "FAIL: divMinInt52 / 1, got " + result + " expected -2251799813685248";
}

// MIN_INT52 / -1 = 2^51 (exceeds MAX_INT52, should OSR exit to double)
function divMinInt52ByNegOne(a, b) {
    return a / b;
}
noInline(divMinInt52ByNegOne);

for (let i = 0; i < testLoopCount; i++) {
    let result = divMinInt52ByNegOne(-2251799813685248, -1);
    if (result !== 2251799813685248)
        throw "FAIL: divMinInt52ByNegOne, got " + result + " expected 2251799813685248";
}

// ===== Large exact divisions =====
function divLargeExact1(a, b) {
    return a / b;
}
noInline(divLargeExact1);

for (let i = 0; i < testLoopCount; i++) {
    let result = divLargeExact1(1099511627776 * 3, 3);  // 2^40 * 3 / 3 = 2^40
    if (result !== 1099511627776)
        throw "FAIL: divLargeExact1, got " + result + " expected 1099511627776";
}

function divLargeExact2(a, b) {
    return a / b;
}
noInline(divLargeExact2);

for (let i = 0; i < testLoopCount; i++) {
    let result = divLargeExact2(-4294967296 * 7, 7);  // -2^32 * 7 / 7 = -2^32
    if (result !== -4294967296)
        throw "FAIL: divLargeExact2, got " + result + " expected -4294967296";
}

// ===== Mixed positive/negative with exact results =====
function divMixed1(a, b) {
    return a / b;
}
noInline(divMixed1);

for (let i = 0; i < testLoopCount; i++) {
    let result = divMixed1(-8589934592, 4);  // -2^33 / 4 = -2^31
    if (result !== -2147483648)
        throw "FAIL: divMixed1, got " + result + " expected -2147483648";
}

function divMixed2(a, b) {
    return a / b;
}
noInline(divMixed2);

for (let i = 0; i < testLoopCount; i++) {
    let result = divMixed2(8589934592, -4);  // 2^33 / -4 = -2^31
    if (result !== -2147483648)
        throw "FAIL: divMixed2, got " + result + " expected -2147483648";
}

// ===== Values just above Int32 range to ensure Int52 path is taken =====
function divJustAboveInt32(a, b) {
    return a / b;
}
noInline(divJustAboveInt32);

for (let i = 0; i < testLoopCount; i++) {
    let result = divJustAboveInt32(2147483648 * 2, 2);  // (2^31 * 2) / 2 = 2^31
    if (result !== 2147483648)
        throw "FAIL: divJustAboveInt32, got " + result + " expected 2147483648";
}

function divJustBelowInt32Min(a, b) {
    return a / b;
}
noInline(divJustBelowInt32Min);

for (let i = 0; i < testLoopCount; i++) {
    let result = divJustBelowInt32Min(-2147483649 * 3, 3);  // -(2^31+1)*3 / 3 = -(2^31+1)
    if (result !== -2147483649)
        throw "FAIL: divJustBelowInt32Min, got " + result + " expected -2147483649";
}

// ===== Alternating values to stress JIT =====
function divAlternating(a, b) {
    return a / b;
}
noInline(divAlternating);

for (let i = 0; i < testLoopCount; i++) {
    let a_val = (i % 2 === 0) ? 1099511627776 * 5 : -1099511627776 * 5;  // ±2^40 * 5
    let result = divAlternating(a_val, 5);
    let expected = a_val / 5;
    if (result !== expected)
        throw "FAIL: divAlternating iteration " + i + ", got " + result + " expected " + expected;
}

// ===== Stress test with various exact divisions =====
function divStress(a, b) {
    return a / b;
}
noInline(divStress);

let int52Values = [
    2147483648, -2147483649, 4294967296, -4294967296,
    1099511627776, -1099511627776, 2251799813685247, -2251799813685248,
    8589934592, -8589934592
];

let exactDivisors = [1, -1, 2, -2, 4, -4, 8, -8];

for (let i = 0; i < testLoopCount; i++) {
    let a = int52Values[i % int52Values.length];
    let b = exactDivisors[i % exactDivisors.length];
    let result = divStress(a, b);
    let expected = a / b;
    if (result !== expected)
        throw "FAIL: divStress a=" + a + " b=" + b + ", got " + result + " expected " + expected;
}

// ===== Computed Int52 division =====
function divComputedInt52(x) {
    let largeValue = x * 2147483648;  // Will be Int52-range
    return largeValue / 2;
}
noInline(divComputedInt52);

let computedExpected = (6 * 2147483648) / 2;
for (let i = 0; i < testLoopCount; i++) {
    let result = divComputedInt52(6);
    if (result !== computedExpected)
        throw "FAIL: computed Int52 div case, got " + result + " expected " + computedExpected;
}
