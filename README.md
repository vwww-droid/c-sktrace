
# sktrace
frida stalker trace

## 功能
1. 类似 ida 指令 trace 功能
2. 统计寄存器变化，辅助分析，并且可能会有字符串产生

## todo
1. arm32

## changelog

### 2025-10-18

1. 改为 C 实现
   1. C before/after callout
   2. 添加数据结构寄存器快照
   3. C 不进行数据处理，使用 Python 异步处理
2. 增加 `-H` `-U` 参数