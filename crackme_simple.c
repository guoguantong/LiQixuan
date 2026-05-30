/* 简化版 crackme — 去掉 strlen/printf/scanf，供 angr 符号执行分析。
   密码逻辑与原版完全一致：
     input[0]=='A' && input[1]=='Z' && (input[2]^0x12)=='q' && (input[3]+3)=='H'
   即密码为: AZcE */

int gadget_trap(void) {
    while (1) { /* 死循环陷阱 */ }
    return 0;
}

int check_password(char *input) {
    /* 检查长度 >= 4（替代 strlen） */
    if (input[0] == 0 || input[1] == 0 || input[2] == 0 || input[3] == 0) {
        return 0;
    }
    if (input[0] == 'A') {
        if (input[1] == 'B') {
            return gadget_trap();
        }
        if (input[1] == 'Z') {
            if ((input[2] ^ 0x12) == 'q') {
                if ((input[3] + 3) == 'H') {
                    return 1;  /* Success! */
                }
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    return check_password(argv[1]);
}
