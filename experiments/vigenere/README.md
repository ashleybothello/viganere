# Vigenère Cipher Simulator with Cryptanalysis

## Group Information

| Field | Details |
|---|---|
| **Group** | Group 1 |
| **Course** | CSS TH ISE — Virtual Lab Development |
| **Class** | TE Computer Engineering — Comp B |
| **Members** | 10642 Alphonso Doris, 10643 Arora Harman Singh, 10644 Bothello Ashley, 10645 Burken Binoy Aurthur, 10646 Cardoza Shaina James |

## Experiment

| Field | Value |
|---|---|
| **Experiment Name** | Vigenère Cipher Simulator with Cryptanalysis |
| **Folder** | `experiments/vigenere/` |
| **Entry File** | `index.html` |
| **Navigation Title** | Vigenère Cipher Simulator with Cryptanalysis |
| **Short Description** | Encrypt and decrypt messages with the Vigenère cipher and observe its resistance to frequency analysis. |

## Required Libraries

**None.** This experiment uses only HTML, CSS, and vanilla JavaScript with no external dependencies.

## Technology

- HTML5
- CSS3
- JavaScript (ES6+)
- No frameworks, no backend, no database

## Input

- **Message**: Plaintext (for encryption) or ciphertext (for decryption)
- **Keyword**: The key used for Vigenère encryption/decryption (alphabetic characters only)

## Output

- **Ciphertext** (from encryption) or **Plaintext** (from decryption)
- **Key stream alignment** showing how the key maps to each character position
- **Step-by-step trace table** showing the arithmetic for each character
- **Frequency analysis data** (counts, percentages, bar charts) for cryptanalysis

## Features

1. **Introduction & Aim** — Academic context and experiment objectives
2. **Theory** — Comprehensive theory section with key terms, formulas, and historical context
3. **Tabula Recta** — Interactive 26×26 Vigenère square with live highlighting during simulation
4. **Encryption** — Enter plaintext and key; view ciphertext, key stream, and step-by-step trace
5. **Decryption** — Enter ciphertext and key; view plaintext, key stream, and step-by-step trace
6. **Step-by-Step Simulation** — Walk through encryption/decryption one character at a time with tabula recta highlighting
7. **Cryptanalysis** — Dynamic frequency analysis with three charts comparing plaintext and ciphertext distributions
8. **Procedure** — Numbered procedure for conducting the experiment
9. **Worked Examples** — Four worked examples with detailed traces
10. **Quiz** — 10 MCQs with shuffled order, immediate feedback, explanations, and scoring
11. **Test Suite** — Automated tests verifying all supplied test vectors and edge cases
12. **References** — Academic references

## Algorithm Summary

The Vigenère cipher encrypts alphabetic text using a keyword-driven polyalphabetic substitution.

### Encryption Formula

```
Cᵢ = (Pᵢ + K(i mod m)) mod 26
```

Where:
- Pᵢ = numeric value of plaintext letter (A=0 … Z=25)
- K(i mod m) = numeric value of corresponding key letter (key repeats with period m)
- Cᵢ = numeric value of resulting ciphertext letter

### Decryption Formula

```
Pᵢ = (Cᵢ − K(i mod m) + 26) mod 26
```

The `+26` ensures the intermediate value is non-negative.

### Cryptanalysis Method

1. Convert text to uppercase, consider only A–Z
2. Count occurrences of each letter
3. Calculate percentage frequency: `(count / total) × 100`
4. Compare plaintext and ciphertext frequency distributions
5. Observe that polyalphabetic encryption flattens the distribution, making single-letter frequency analysis less effective

## Test Cases

### Encryption

| ID | Plaintext | Key | Expected Ciphertext |
|---|---|---|---|
| TC-ENC-01 | `ATTACKATDAWN` | `LEMON` | `LXFOPVEFRNHR` |
| TC-ENC-01b | `ATTACK AT DAWN` | `LEMON` | `LXFOPV EF RNHR` |
| TC-ENC-02 | `Att ack at Dawn!` | `lemon` | `Lxf opv ef Rnhr!` |
| TC-ENC-03 | `HELLO` | `A` | `HELLO` |
| TC-ENC-04 | `CRYPTOGRAPHY` | `VERYLONGKEY…` | `XVPNECTXKTFU` |

### Decryption

| ID | Ciphertext | Key | Expected Plaintext |
|---|---|---|---|
| TC-DEC-01 | `LXFOPVEFRNHR` | `LEMON` | `ATTACKATDAWN` |
| TC-DEC-01b | `LXFOPV EF RNHR` | `LEMON` | `ATTACK AT DAWN` |
| TC-DEC-02 | `Lxf opv ef Rnhr!` | `lemon` | `Att ack at Dawn!` |
| TC-DEC-03 | `HELLO` | `A` | `HELLO` |
| TC-DEC-04 | `XVPNECTXKTFU` | `VERYLONGKEY…` | `CRYPTOGRAPHY` |

### Edge Cases

| ID | Scenario | Expected Behavior |
|---|---|---|
| TC-EDGE-01 | Empty key | Error message |
| TC-EDGE-02 | Key = `123!@#` | Error (no letters) |
| TC-EDGE-03 | Key = `L3M*N` | Sanitised to `LMN`, encrypts normally |
| TC-EDGE-04 | Empty plaintext | Empty ciphertext |

### Inverse Property

For all test pairs: `decrypt(encrypt(P, K), K) === P`

### Frequency Validation

For `ATTACKATDAWN` / `LEMON`:

- Plaintext: `[4,0,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,0,0,3,0,0,1,0,0,0]`
- Ciphertext: `[0,0,0,0,1,1,0,1,0,0,0,1,0,1,1,1,0,2,0,0,0,1,0,1,0,0]`

## Viva / Evaluation Questions

1. **What is a polyalphabetic cipher?**
   A cipher that uses multiple substitution alphabets, cycling through them based on a keyword. Each key letter selects a different Caesar shift.

2. **How does the Vigenère cipher differ from a Caesar cipher?**
   Caesar uses a single fixed shift (monoalphabetic); Vigenère uses multiple shifts determined by a keyword (polyalphabetic).

3. **State the encryption and decryption formulas.**
   Encryption: Cᵢ = (Pᵢ + K(i mod m)) mod 26. Decryption: Pᵢ = (Cᵢ − K(i mod m) + 26) mod 26.

4. **Why is the `+26` needed in the decryption formula?**
   To ensure the value is non-negative before taking mod 26. For example, if C=5 and K=12, then 5−12 = −7; adding 26 gives 19, and 19 mod 26 = 19 (letter T).

5. **What happens when a non-alphabetic character is encountered?**
   It passes through unchanged in the output, and the key pointer does NOT advance to the next key letter.

6. **If the key is a single letter, what cipher does Vigenère reduce to?**
   A Caesar cipher with the shift equal to the key letter's value.

7. **Encrypt "ATTACK AT DAWN" with key "LEMON" — what is the ciphertext?**
   LXFOPV EF RNHR.

8. **Why is single-letter frequency analysis less effective against Vigenère?**
   Because the same plaintext letter is encrypted to different ciphertext letters depending on the key letter at that position, disrupting the one-to-one frequency correspondence.

9. **What is Kasiski examination?**
   A method for breaking Vigenère by finding repeated sequences in the ciphertext; the distances between repetitions are likely multiples of the key length.

10. **For a key length of 5, how many possible Vigenère keys exist?**
    26⁵ = 11,881,376.

## Quiz Description

The experiment includes a 10-question multiple-choice quiz covering:
- Polyalphabetic vs. monoalphabetic ciphers
- Letter-to-number mapping (A=0…Z=25)
- Encryption and decryption formulas
- Key repetition behaviour
- Single-character key behaviour
- Frequency analysis resistance
- Key length and security
- Kasiski examination
- Non-alphabetic character handling

Questions are shuffled on each attempt. Options are shuffled per question. Immediate feedback with explanations is provided. A final score and percentage are displayed.

## How to Run

1. Open `experiments/vigenere/index.html` in any modern web browser.
2. No build step, server, or installation is required.
3. Navigate using the sidebar menu.

## Integration Notes

- Self-contained module with no external dependencies.
- Can be integrated into a larger virtual lab site by linking to or embedding `index.html`.
- No build tools, frameworks, or package managers required.
- Uses Google Fonts (Inter, JetBrains Mono) loaded via CDN; works offline with system fallback fonts.

## Known Limitations

- The frequency analysis is based on single-letter frequency only; it does not implement full Kasiski examination or index of coincidence calculation (these are discussed in theory).
- Charts are rendered using HTML Canvas (no external library); they are functional but not interactive (no hover tooltips).
- The experiment focuses on the classical 26-letter English alphabet (A–Z); extended character sets are not supported.
