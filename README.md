XOR, ROTATION, ADDICTION, NOT, SHA3-256 사용
블록크기 : 128bit 키크기 : 256bit 라운드횟수 : 32

암호화 키 앞부분 : key[0] 뒷부분 : key[1]
1. data[i] = data[i] + data[i+1] // 0<=i<N   0->N
2. data[N] = data[N]  + key[0]
3. data[i] = data[i] ^ key[1] // 0<=i<=N
4. data[i] = rotate_r(data[i], i) // 0<=i<=N
5. data[i] = data[i] + data[i-1] // 0<i<=N   N->0
6. data[0] = data[0] + key[0] // 0<i<=N
7. data[i] = ~data[i] // 0<=i<=N
8. key = sha3(key)
9. 1~9 32번 반복

sha3 : kisa소스 https://seed.kisa.or.kr/kisa/Board/79/detailView.do
