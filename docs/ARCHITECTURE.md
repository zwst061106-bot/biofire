# Architecture Documentation

## MPC-CMP Protocol Flow

### 1. DKG (Distributed Key Generation)

```
Node 1: f_1(x) = a_1,0 + a_1,1·x + ... + a_1,t-1·x^(t-1)
Node 2: f_2(x) = a_2,0 + a_2,1·x + ... + a_2,t-1·x^(t-1)
...
Node n: f_n(x) = a_n,0 + a_n,1·x + ... + a_n,t-1·x^(t-1)

Share for Node j: s_j = Σ f_i(j)
Public Key: PK = Σ a_i,0 · G
```

### 2. Threshold Signing

```
1. Each signer generates independent nonce k_i
2. Compute R_i = k_i · G
3. MtA exchange: α + β = x·y (mod q)
4. Partial signature: s_i = k_i⁻¹(z + r·x_i) (mod q)
5. Combine: s = Σ λ_i · s_i (mod q)
```

### 3. Security Properties

- **No single point of failure**: t-1 compromised nodes cannot sign
- **Identifiable abort**: Malicious nodes detected and excluded
- **Proactive security**: Key refresh without changing public key
