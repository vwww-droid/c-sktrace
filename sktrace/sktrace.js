

const arm64CM = new CModule(`
#include <gum/gumstalker.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void on_message(const gchar *message);
extern void on_register_change(gpointer addr, int reg_idx, guint64 old_val, guint64 new_val);
static void log(const gchar *format, ...);
static void on_arm64_before(GumCpuContext *cpu_context, gpointer user_data);
static void on_arm64_after(GumCpuContext *cpu_context, gpointer user_data);
void flush_buffer();  // Export for JS

void hello() {
    on_message("Hello form CModule");
}

// 使用 shared_mem 保存寄存器状态
#define SHARED_MEM_SIZE 64
static guint64 shared_mem[SHARED_MEM_SIZE];

gpointer 
get_shared_mem() 
{
    return shared_mem;
}

// 寄存器索引定义
#define IDX_BEFORE_X0 0
#define IDX_BEFORE_SP 1

static void
log(const gchar *format, ...)
{
    gchar *message;
    va_list args;

    va_start(args, format);
    message = g_strdup_vprintf(format, args);
    va_end(args);

    on_message(message);
    g_free(message);
}

// 空函数
void
flush_buffer()
{
    log("[flush_buffer] Called");
}


void transform(GumStalkerIterator *iterator,
               GumStalkerOutput *output,
               gpointer user_data)
{
    cs_insn *insn;

    gpointer base = *(gpointer*)user_data;
    gpointer end = *(gpointer*)(user_data + sizeof(gpointer));
    
    while (gum_stalker_iterator_next(iterator, &insn))
    {
        gboolean in_target = (gpointer)insn->address >= base && (gpointer)insn->address < end;
        if(in_target)
        {
            // 输出指令信息 (使用 tab 分隔)
            log("%p\t%s\t%s", (gpointer)insn->address, insn->mnemonic, insn->op_str);
            gum_stalker_iterator_put_callout(iterator, on_arm64_before, (gpointer) insn->address, NULL);
        }
        gum_stalker_iterator_keep(iterator);
        if(in_target) 
        {
            gum_stalker_iterator_put_callout(iterator, on_arm64_after, (gpointer) insn->address, NULL);
        }
    }
}


const gchar * cpu_format = "
    0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x
    ";

static void
on_arm64_before(GumCpuContext *cpu_context,
        gpointer user_data)
{
    // 空 - 不做 before 快照
}

static void
on_arm64_after(GumCpuContext *cpu_context,
        gpointer user_data)
{
    // 输出所有寄存器，Python 端做比较
    // 格式: addr|x0|x1|x2|...|x28|fp|lr|sp|pc
    if (cpu_context) {
        log("%p|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|"
            "%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|"
            "%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|%llx|"
            "%llx|%llx|%llx|%llx",
            user_data,
            cpu_context->x[0], cpu_context->x[1], cpu_context->x[2], cpu_context->x[3],
            cpu_context->x[4], cpu_context->x[5], cpu_context->x[6], cpu_context->x[7],
            cpu_context->x[8], cpu_context->x[9], cpu_context->x[10], cpu_context->x[11],
            cpu_context->x[12], cpu_context->x[13], cpu_context->x[14], cpu_context->x[15],
            cpu_context->x[16], cpu_context->x[17], cpu_context->x[18], cpu_context->x[19],
            cpu_context->x[20], cpu_context->x[21], cpu_context->x[22], cpu_context->x[23],
            cpu_context->x[24], cpu_context->x[25], cpu_context->x[26], cpu_context->x[27],
            cpu_context->x[28],
            cpu_context->fp, cpu_context->lr, cpu_context->sp, cpu_context->pc);
    }
}

`, {
    on_message: new NativeCallback(messagePtr => {
        const message = messagePtr.readUtf8String();
        // 发送到 Python 端，不在 console 打印（避免重复）
        send({
            type: 'c_output',
            tid: currentTid,
            message: message
        });
      }, 'void', ['pointer']),
    on_register_change: new NativeCallback((addr, reg_idx, old_val, new_val) => {
        // C 调用这个回调发送寄存器变化
        try {
            if (!currentTid) return;
            
            // 构造寄存器名
            const regNames = [
                'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9',
                'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18', 'x19',
                'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28',
                'fp', 'lr', 'sp', 'pc'
            ];
            const regName = regNames[reg_idx] || `reg${reg_idx}`;
            
            // 发送格式化消息给 Python
            send({
                type: 'c_reg_change',
                tid: currentTid,
                addr: addr.toString(),
                reg: regName,
                old: '0x' + old_val.toString(16),
                new: '0x' + new_val.toString(16)
            });
        } catch (e) {
            console.error('[on_register_change] Error:', e.message);
        }
      }, 'void', ['pointer', 'int', 'uint64', 'uint64']),
});

let currentTid = null;  // 全局变量保存当前 tid

const userData = Memory.alloc(Process.pageSize);
function stalkerTraceRangeC(tid, base, size) {
    currentTid = tid;  // 保存 tid
    
    userData.writePointer(base)
    const pointerSize = Process.pointerSize;
    userData.add(pointerSize).writePointer(base.add(size))
    
    Stalker.follow(tid, {
        transform: arm64CM.transform,
        data: userData
    })
}

// 导出 C 的 flush 函数，让 JS 可以调用
function flushCBuffer(tid) {
    const flushBuffer = new NativeFunction(arm64CM.flush_buffer, 'void', []);
    flushBuffer();
}


function stalkerTraceRange(tid, base, size) {
    Stalker.follow(tid, {
        transform: (iterator) => {
            const instruction = iterator.next();
            const startAddress = instruction.address;
            const isModuleCode = startAddress.compare(base) >= 0 && 
                startAddress.compare(base.add(size)) < 0;
            // const isModuleCode = true;
            do {
                iterator.keep();
                if (isModuleCode) {
                    send({
                        type: 'inst',
                        tid: tid,
                        block: startAddress,
                        val: JSON.stringify(instruction)
                    })
                    iterator.putCallout((context) => {
                            send({
                                type: 'ctx',
                                tid: tid,
                                val: JSON.stringify(context)
                            })
                    })
                }
            } while (iterator.next() !== null);
        }
    })
}


function traceAddr(addr) {
    let moduleMap = new ModuleMap();    
    let targetModule = moduleMap.find(addr);
    console.log(JSON.stringify(targetModule))
    let exports = targetModule.enumerateExports();
    let symbols = targetModule.enumerateSymbols();
    // send({
    //     type: "module", 
    //     targetModule
    // })
    // send({
    //     type: "sym",
    

    // })
    Interceptor.attach(addr, {
        onEnter: function(args) {
            try {
                this.tid = Process.getCurrentThreadId()
                console.log('[onEnter] Starting C trace for tid:', this.tid);
                stalkerTraceRangeC(this.tid, targetModule.base, targetModule.size);  // 使用 C 版本
                // stalkerTraceRange(this.tid, targetModule.base, targetModule.size)
            } catch (e) {
                console.error('[onEnter] Error:', e.message, e.stack);
            }
        },
        onLeave: function(ret) {
            try {
                console.log('[onLeave] Flushing buffer for tid:', this.tid);
                // 在函数返回时刷新缓冲区
                flushCBuffer(this.tid);
                
                Stalker.unfollow(this.tid);
                Stalker.garbageCollect()
                send({
                    type: "fin",
                    tid: this.tid
                })
            } catch (e) {
                console.error('[onLeave] Error:', e.message, e.stack);
            }
        }
    })
}


function traceSymbol(symbol) {

}

/**
 * from jnitrace-egine
 */
function watcherLib(libname, callback) {
    const dlopenRef = Module.findExportByName(null, "dlopen");
    const dlsymRef = Module.findExportByName(null, "dlsym");
    const dlcloseRef = Module.findExportByName(null, "dlclose");

    if (dlopenRef !== null && dlsymRef !== null && dlcloseRef !== null) {
        const dlopen = new NativeFunction(dlopenRef, "pointer", ["pointer", "int"]);
        Interceptor.replace(dlopen, new NativeCallback((filename, mode) => {
            const path = filename.readCString();
            const retval = dlopen(filename, mode);
    
            if (path !== null) {
                if (checkLibrary(path)) {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    trackedLibs.set(retval.toString(), true);
                } else {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    libBlacklist.set(retval.toString(), true);
                }
            }

            return retval;
        }, "pointer", ["pointer", "int"]));
    }
}



(() => {

    console.log(`----- start trace -----`);

    recv("config", (msg) => {
        const payload = msg.payload;
        console.log(JSON.stringify(payload))
        const libname = payload.libname;
        console.log(`libname:${libname}`)
        if(payload.spawn) {
            console.error(`todo: spawn inject not implemented`)
        } else {
            // const modules = Process.enumerateModules();
            const targetModule = Process.getModuleByName(libname);
            let targetAddress = null;
            if("symbol" in payload) {
                targetAddress = targetModule.findExportByName(payload.symbol);
            } else if("offset" in payload) {
                targetAddress = targetModule.base.add(ptr(payload.offset));
            }
            traceAddr(targetAddress)
        }
    })
})()