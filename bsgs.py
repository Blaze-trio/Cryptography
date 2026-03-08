import time

p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171
g = 11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568
h = 3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333

# B = 2^20
B = 2**20

start_time = time.time()

print("Phase 1: Building the hash table (Baby Steps)...")

baby_steps = {}

g_inv = pow(g, p - 2, p)

current_lhs = h
for x1 in range(B + 1):
    baby_steps[current_lhs] = x1
    current_lhs = (current_lhs * g_inv) % p

print(f"Phase 1 complete in {time.time() - start_time:.2f} seconds.")
print("Phase 2: Searching the table (Giant Steps)...")

g_B = pow(g, B, p)
current_rhs = 1

for x0 in range(B + 1):
    if current_rhs in baby_steps:
        x1 = baby_steps[current_rhs]

        x = x0 * B + x1
        
        print("\n--- SUCCESS ---")
        print(f"Found x0 = {x0}, x1 = {x1}")
        print(f"Discrete Log (x) = {x}")
        
        print(f"Verification Check (g^x mod p == h): {pow(g, x, p) == h}")
        break

    current_rhs = (current_rhs * g_B) % p

print(f"Total time elapsed: {time.time() - start_time:.2f} seconds.")