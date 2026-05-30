/* 简化版 crackme — 去掉 printf/scanf，只保留核心密码检查逻辑。
   这样 angr 的符号执行可以直接分析，不会被 libc 函数干扰。 */

int gadget_trap(void) {
    while (1) {
        /* 死循环陷阱 */
    }
    return 0;
}

int check_password(char *input) {
    if (input[0] == 'A') {
        if (input[1] == 'B') {
            return gadget_trap();  /* 陷阱路径：返回 -1 表示陷阱 */
        }
        if (input[1] == 'Z') {
            return 1;              /* Success 路径：返回 1 */
        }
    }
    return 0;                      /* 失败路径：返回 0 */
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    return check_password(argv[1]);
}
