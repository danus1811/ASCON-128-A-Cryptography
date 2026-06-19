The growing demand for secure and efficient cryptographic solutions in embedded and 
IoT systems necessitates hardware architectures that balance performance, area, and 
power consumption. This work presents a lightweight System-on-Chip (SoC) that inte- 
grates a RISC-V processor with a dedicated ASCON hardware unit for authenticated 
encryption and decryption. The SoC combines a PicoRV32 processor, on-chip memories, 
and a memory-mapped ASCON core unit connected through a centralized address de- 
coder, enabling seamless software–hardware interaction. The proposed design achieves a 
throughput of 711.11 Mbps at a maximum operating frequency of 250 MHz, with a gate 
count of 25.899 kGE and a core area of 98,008.71 µm2 in a 90 nm CMOS technology. 
Functional correctness is validated across official NIST(SP 800-232) test vectors, and 
formal equivalence checking confirms consistency between RTL and gate-level 
implementations for both en- cryption and decryption. Post-layout results demonstrate 
full sign-off cleanliness, with zero connectivity, design rule, and timing violations, 
confirming that the design is phys- ically realizable, timing-clean, and ready for silicon 
fabrication. Overall, the proposed SoC provides a robust and scalable solution suitable for 
secure embedded and IoT applications.
