import math

def isqrt(n):
    if n < 0:
        raise ValueError("Square root not defined for negative numbers")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

# Challenge 1: |p - q| < 2 * N^(1/4)
def factor_challenge_1(N):
    A = isqrt(N) + 1
    x2 = A**2 - N
    x = isqrt(x2)
    if x**2 == x2:
        p = A - x
        q = A + x
        return min(p, q)

# Challenge 2: |p - q| < 2^11 * N^(1/4)
def factor_challenge_2(N):
    A = isqrt(N) + 1
    while True:
        x2 = A**2 - N
        # Quick modulo check to bypass expensive square roots for non-squares
        if x2 % 16 in (0, 1, 4, 9): 
            x = isqrt(x2)
            if x**2 == x2:
                p = A - x
                q = A + x
                return min(p, q)
        A += 1

# Challenge 3: |3p - 2q| < N^(1/4)
def factor_challenge_3(N):
    # 3p is odd, 2q is even, so (3p + 2q) is odd — direct Fermat on 6N fails.
    # Use: (3p+2q)^2 - (3p-2q)^2 = 24N
    # Search odd s near sqrt(24N) such that s^2 - 24N = d^2 (perfect square)
    target = 24 * N
    s = isqrt(target)
    if s % 2 == 0:
        s += 1  # ensure s is odd
    while True:
        d2 = s * s - target
        if d2 >= 0:
            d = isqrt(d2)
            if d * d == d2:
                # s = 3p + 2q, d = |3p - 2q|; both odd so (s±d) are even
                u = (s + d) // 2  # candidate for 3p
                v = (s - d) // 2  # candidate for 2q
                if u % 3 == 0 and v % 2 == 0:
                    p, q = u // 3, v // 2
                    if p * q == N:
                        return min(p, q)
                if v % 3 == 0 and u % 2 == 0:
                    p, q = v // 3, u // 2
                    if p * q == N:
                        return min(p, q)
        s += 2  # keep s odd

N1 = 179769313486231590772930519078902473361797697894230657273430081157732675805505620686985379449212982959585501387537164015710139858647833778606925583497541085196591615128057575940752635007475935288710823649949940771895617054361149474865046711015101563940680527540071584560878577663743040086340742855278549092581
N2 = 648455842808071669662824265346772278726343720706976263060439070378797308618081116462714015276061417569195587321840254520655424906719892428844841839353281972988531310511738648965962582821502504990264452100885281673303711142296421027840289307657458645233683357077834689715838646088239640236866252211790085787877
N3 = 720062263747350425279564435525583738338084451473999841826653057981916355690188337790423408664187663938485175264994017897083524079135686877441155132015188279331812309091996246361896836573643119174094961348524639707885238799396839230364676670221627018353299443241192173812729276147530748597302192751375739387929

print("Challenge 1:", factor_challenge_1(N1))
print("Challenge 2:", factor_challenge_2(N2))
print("Challenge 3:", factor_challenge_3(N3))

# The ciphertext provided in Challenge 4
C = 22096451867410381776306561134883418017410069787892831071731839143676135600120538004282329650473509424343946219751512256465839967942889460764542040581564748988013734864120452325229320176487916666402997509188729971690526083222067771600019329260870009579993724077458967773697817571267229951148662959627934791540
e = 65537

def decrypt_challenge_4(p, q, ciphertext, e):
    N = p * q
    
    # 1. Compute Euler's Totient Function, phi(N)
    phi = (p - 1) * (q - 1)
    
    # 2. Compute the private decryption exponent 'd' via Extended Euclidean Algorithm
    def modinv(a, m):
        g, x = m, 0
        a0, x0 = a, 1
        while a0 != 0:
            q = g // a0
            g, a0 = a0, g - q * a0
            x, x0 = x0, x - q * x0
        return x % m
    d = modinv(e, phi)
    
    # 3. Core RSA Decryption: m = C^d mod N
    m_int = pow(ciphertext, d, N)
    
    # 4. Convert the resulting massive integer into a hexadecimal string
    m_hex = hex(m_int)[2:] # The [2:] strips the '0x' prefix
    
    # Ensure the hex string has an even number of characters to map to bytes
    if len(m_hex) % 2 != 0:
        m_hex = '0' + m_hex
        
    # Convert the hex string into raw bytes
    m_bytes = bytes.fromhex(m_hex)
    
    # 5. Parse the PKCS#1 v1.5 Padding
    # As the prompt noted, the integer drops the leading 0x00, so it starts at 0x02.
    # We need to scan forward to find the 0x00 byte that separates the random padding from the plaintext.
    
    separator_index = m_bytes.find(b'\x00', 1) # Start searching after the initial 0x02 byte
    
    if separator_index != -1:
        # Extract everything after the 0x00 separator
        plaintext_bytes = m_bytes[separator_index + 1:]
        
        # Decode the bytes back into human-readable English ASCII
        return plaintext_bytes.decode('ascii')
    else:
        return "Error: Could not find the 0x00 separator byte."

# Assuming you saved the outputs from the previous script
p1 = factor_challenge_1(N1)
q1 = N1 // p1
print("Secret Message:", decrypt_challenge_4(p1, q1, C, e))
