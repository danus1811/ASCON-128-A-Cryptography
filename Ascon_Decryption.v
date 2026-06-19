// ASCON DECRYPTION WRAPPER MODULE
//
// ENDIANNESS ANALYSIS (mirrors Ascon_Encryption wrapper exactly):
//
// KEY and NONCE: MUST be byte-swapped word-by-word.
//   Placed directly into 64-bit state word slots; NIST requires
//   little-endian integer representation for each 64-bit word.
//   The serial shift register captures MSB-first (big-endian), so
//   each 64-bit word is byte-reversed before entering the core.
//
// AD and CT: NOT byte-swapped.
//   The core absorbs AD/CT as an MSB-first bit-string, consistent
//   with the reference implementation and the encryption wrapper.
//
// TAG output: MUST be byte-swapped back.
//   The core produces two LE 64-bit words; each is byte-reversed to
//   yield the big-endian tag the testbench/user expects.
//
// PT output: NOT byte-swapped.
//   Same convention as CT input (and CT output of encryption).

module Ascon_Decryption #(
    parameter k = 128,
    parameter r = 128,   // Rate: 128 for AEAD128
    parameter a = 12,
    parameter b = 8,
    parameter l = 40,
    parameter y = 40,
    parameter v = 1      // AEAD128 variant identifier
)(
    input       clk,
    input       rst,
    input       keyxSI,
    input       noncexSI,
    input       associated_dataxSI,
    input       cipher_textxSI,
    input       decryption_startxSI,
    output reg  plain_textxSO,
    output reg  tagxSO,
    output      decryption_readyxSO
);

    // ------------------------------------------------------------------
    // CNT_MAX: counter must cover the largest of k, 128, l, y so that
    // every shift register is fully loaded before ready is asserted.
    // ------------------------------------------------------------------
    localparam CNT_MAX = (k  >= 128 ? k  : 128) >= l ?
                         (k  >= 128 ? k  : 128) >= y ?
                         (k  >= 128 ? k  : 128)       : y
                       : l >= y ? l : y;

    // ------------------------------------------------------------------
    // Internal shift registers ? raw MSB-first serial capture
    // ------------------------------------------------------------------
    reg  [k-1:0]  key;
    reg  [127:0]  nonce;
    reg  [l-1:0]  associated_data;
    reg  [y-1:0]  cipher_text;
    reg  [31:0]   i, j;

    // ------------------------------------------------------------------
    // bswap64: reverse byte order within one 64-bit word.
    // Converts MSB-first (big-endian) serial-captured value into the
    // little-endian 64-bit integer the core state words require.
    // ------------------------------------------------------------------
    function [63:0] bswap64;
        input [63:0] x;
        bswap64 = { x[ 7: 0], x[15: 8], x[23:16], x[31:24],
                    x[39:32], x[47:40], x[55:48], x[63:56] };
    endfunction

    // ------------------------------------------------------------------
    // KEY: 128 bits = two 64-bit state words, each byte-swapped.
    // ------------------------------------------------------------------
    wire [127:0] key_le;
    assign key_le = { bswap64(key[127:64]),
                      bswap64(key[ 63: 0]) };

    // ------------------------------------------------------------------
    // NONCE: 128 bits = two 64-bit state words, each byte-swapped.
    // ------------------------------------------------------------------
    wire [127:0] nonce_le;
    assign nonce_le = { bswap64(nonce[127:64]),
                        bswap64(nonce[ 63: 0]) };

    // ------------------------------------------------------------------
    // PT: passed straight through from core to serial output.
    // ------------------------------------------------------------------
    wire [y-1:0]  plain_text;

    // ------------------------------------------------------------------
    // TAG: two 64-bit words in LE format from the core.
    // Byte-swap each word back to big-endian for the user/testbench.
    // ------------------------------------------------------------------
    wire [127:0] tag_core;
    wire [127:0] tag;
    assign tag = { bswap64(tag_core[127:64]),
                   bswap64(tag_core[ 63: 0]) };

    // ------------------------------------------------------------------
    // Ready / start logic
    // ready is asserted once every shift register has been fully loaded.
    // ------------------------------------------------------------------
    wire ready            = (i >= k) && (i >= 128) && (i >= l) && (i >= y);
    wire decryption_start = ready & decryption_startxSI;
    wire decryption_ready;
    assign decryption_readyxSO = decryption_ready;

    // ------------------------------------------------------------------
    // Serial-in / serial-out shift registers
    // ------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            key             <= 0;
            nonce           <= 0;
            associated_data <= 0;
            cipher_text     <= 0;
            i               <= 0;
            j               <= 0;
            plain_textxSO   <= 0;
            tagxSO          <= 0;
        end else begin
            // Shift in one bit per clock while the register still needs bits
            if (i < k)   key             <= {key[k-2:0],            keyxSI};
            if (i < 128) nonce           <= {nonce[126:0],           noncexSI};
            if (i < l)   associated_data <= {associated_data[l-2:0], associated_dataxSI};
            if (i < y)   cipher_text     <= {cipher_text[y-2:0],     cipher_textxSI};

            // Counter: increment until CNT_MAX bits have been clocked in
            if (i <= CNT_MAX) i <= i + 1;

            // Reset output serialiser when a new decryption begins
            if (decryption_start)
                j <= 0;

            // Serialise outputs LSB-first once decryption is done
            if (decryption_ready) begin
                plain_textxSO <= (j < y)   ? plain_text[j] : 1'b0;
                tagxSO        <= (j < 128) ? tag[j]        : 1'b0;
                j <= j + 1;
            end
        end
    end

    // ------------------------------------------------------------------
    // Decryption core
    // ------------------------------------------------------------------
    Decryption #(k, r, a, b, l, y, v) decryption_core (
        .clk              (clk),
        .rst              (rst),
        .key              (key_le),
        .nonce            (nonce_le),
        .associated_data  (associated_data),
        .cipher_text      (cipher_text),
        .decryption_start (decryption_start),
        .plain_text       (plain_text),
        .tag              (tag_core),
        .decryption_ready (decryption_ready)
    );

endmodule
