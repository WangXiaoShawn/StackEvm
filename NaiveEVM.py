import sha3 # pip install safe-pysha3
import pdb
STOP = 0x00
ADD = 0x01
MUL = 0x02
SUB = 0x03
DIV = 0x04
SDIV = 0x05
MOD = 0x06
SMOD = 0x07
ADDMOD = 0x08
MULMOD = 0x09
EXP = 0x0A
SIGNEXTEND = 0x0B
LT = 0x10
GT = 0x11
SLT = 0x12
SGT = 0x13
EQ = 0x14
ISZERO = 0x15
AND = 0x16
OR = 0x17
XOR = 0x18
NOT = 0x19
BYTE = 0x1A
SHL = 0x1B
SHR = 0x1C
SAR = 0x1D
SHA3 = 0x20
ADDRESS = 0x30
BALANCE = 0x31
ORIGIN = 0x32
CALLER = 0x33
CALLVALUE = 0x34
CALLDATALOAD = 0x35
CALLDATASIZE = 0x36
CALLDATACOPY = 0x37
CODESIZE = 0x38
CODECOPY = 0x39
GASPRICE = 0x3A
EXTCODESIZE = 0x3B
EXTCODECOPY = 0x3C
EXTCODEHASH = 0x3F
BLOCKHASH = 0x40
COINBASE = 0x41
TIMESTAMP = 0x42
NUMBER = 0x43
PREVRANDAO = 0x44
GASLIMIT = 0x45
CHAINID = 0x46
SELFBALANCE = 0x47
BASEFEE = 0x48
PUSH0 = 0x5F
PUSH1 = 0x60
PUSH32 = 0x7F
DUP1 = 0x80
DUP16 = 0x8F
SWAP1 = 0x90
SWAP16 = 0x9F
POP = 0x50
MLOAD = 0x51
MSTORE = 0x52
MSTORE8 = 0x53
SLOAD = 0x54
SSTORE = 0x55
JUMP = 0x56
JUMPI = 0x57
PC = 0x58
MSIZE = 0x59
JUMPDEST = 0x5B
LOG0 = 0xA0
LOG1 = 0xA1
LOG2 = 0xA2
LOG3 = 0xA3
LOG4 = 0xA4
class StopException(Exception):
    pass
#可能的问题就是0XFFFFFFFFFFFFFFFFFFF这样的数，如果是有符号数，那么就是-1，如果是无符号数，那么就是2^256-1这个怎么识别呢
account_db = {
    '0x9bbfed6889322e016e0a02ee459d306fc19545d8': {
        'balance': 100, # wei #这是账户持有的ETH数量，用Wei表示（1 ETH = 10^18 Wei）。
        'nonce': 1, #对于外部账户（EOA），这是该账户发送的交易数。对于合约账户，它是该账户创建的合约数量。
        'storage': {}, #每个合约账户都有与之关联的存储空间，其中包含状态变量的值。address => {key => value}
        'code': b'\x60\x00\x60\x00'  # Sample bytecode (PUSH1 0x00 PUSH1 0x00) #合约账户的字节码。
    },
    # ... 其他账户数据 ...
}
class Log:
    def __init__(self, address, data, topics=[]):
        self.address = address #这代表产生日志的智能合约的地址 例如，如果合约 0x123... 产生了一个日志，那么 address 将是 0x123...。
        self.data = data #字段包含了日志事件中的具体数据。这些数据通常是关于合约操作的详细信息，例如，一个交易的金额、用户地址、或其他合约特定的数据点。
        self.topics = topics #是用于索引日志的参数数组。每个日志可以有一个到四个主题。第一个主题通常是事件的哈希（在合约中定义的事件名称的哈希），其余的主题可以是事件参数的哈希值。
    def __str__(self):
        return  f'Log(address={self.address}, data={self.data}, topics={self.topics})'
class Transaction:
    def __init__(self, to = '', value = 0, data = '', caller='0x00', origin='0x00', thisAddr='0x00', gasPrice=1, gasLimit=21000, nonce=0, v=0, r=0, s=0):
        self.nonce = nonce #一个与发送者账户相关的数字，表示该账户已发送的交易数。
        self.gasPrice = gasPrice #交易发送者愿意支付的单位gas价格。
        self.gasLimit = gasLimit #交易发送者为这次交易分配的最大gas数量。
        self.to = to #交易的接收者地址。当交易为合约创建时，这一字段为空。
        self.value = value #以wei为单位的发送金额。
        self.data = data #附带的数据，通常为合约调用的输入数据（calldata）或新合约的初始化代码（initcode）。
        self.caller = caller #包含当前调用者caller
        self.origin = origin
        #当用户创建（部署）一个新的智能合约时，这个用户就是原始发送者。在这种情况下，origin 就是部署合约的用户的地址。
        #当用户发送一个交易以调用已部署的智能合约时，该用户也是原始发送者。即使这个调用触发了合约与合约之间的进一步交互，origin 仍然是最初发起交易的用户地址。
        self.thisAddr = thisAddr #代表当前合约的地址。在合约执行期间，thisAddr 通常指向执行合约代码的地址。
        self.v = v #交易的签名信息，用于验证交易发送者的身份。
        self.r = r #交易的签名信息，用于验证交易发送者的身份。
        self.s = s #交易的签名信息，用于验证交易发送者的身份。
        
class EVM:
    def __init__(self,code,txn = None) -> None:
        self.code = code
        self.pc = 0
        self.gas = 0
        self.stack = []
        self.memory = bytearray()  # 每一个元素都是8 bit， 1 byte 每个元素可以存储从0到255的整数值
        self.warm_address = set() # 用于存储warm slot 这是一个set 用于存储地址
        self.storage = {}
        self.validJumpDest ={} #有效的跳转地址字典
        #EVM提供了一系列指令让智能合约访问当前或历史区块的信息，包括区块哈希、时间戳、coinbase等。
        #这些信息一般保存在区块头（Header）中，但我们可EVM中添加current_block属性来模拟这些区块信息：
        self.txn = txn
        self.logs = []
        self.current_block = { 
             "blockhash": 0x7527123fc877fe753b3122dc592671b4902ebf2b325dd2c7224a43c0cbeee3ca, # 这是区块的哈希值，是区块的唯一标识符
             "coinbase": 0x388C818CA8B9251b393131C08a736A67ccB19297,# 这通常指的是区块的矿工地址，即创建这个区块的矿工的以太坊地址
             "timestamp": 1625900000,#这是区块的时间戳，表示区块被创建的时间
             "number": 17871709,#: 这是区块的编号，即它在区块链中的序列号
             "prevrandao": 0xce124dee50136f3f93f19667fb4198c6b94eecbacfa300469e5280012757be94,# 这个字段通常与区块的随机性相关，可能是前一个区块的随机数种子或类似的值
             "gaslimit": 30,#这表示区块的 Gas 限制，即区块中所有交易可以消耗的最大 Gas 总量
             "chainid": 1,#这是区块链的标识符，用于区分不同的以太坊网络。例如，1 通常代表以太坊主网
             "selfbalance": 100,# 表示与当前执行环境或合约相关的余额
             "basefee": 30,#这是区块的基础费用，是以太坊网络中EIP-1559机制引入的概念，用于确定交易费用的基准价格。在这个例子中，基础费用是 30。
        }
    def next_instruction(self):
        op = self.code[self.pc]
        self.pc += 1
        return op
    def push(self,size):
        data = self.code[self.pc:self.pc+size]# 从pc开始，取size个字节 左闭右开
        value = int.from_bytes(data,"big") #吧二进制数据转化从整数 Big-endian 最左的是最高位
        self.stack.append(value)
        self.pc += size # pc指向下一条指令
    def pop(self):
        if len(self.stack) == 0:
            raise Exception("Stack underflow")
        return self.stack.pop() # 弹出栈
    def add(self): #从栈顶弹出两个数，相加，结果压入栈顶，如果不足两个元素则异常
        if (len(self.stack) < 2):
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        res = (a + b) % (2**256) # 因为stack中的数都是256位的（read0-write 256bit），所以要对2^256取模
        self.stack.append(res)
    def mul (self): #从栈顶弹出两个数，相乘，结果压入栈顶，如果不足两个元素则异常
        if (len(self.stack) < 2):
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        res = (a * b) % (2**256)
        self.stack.append(res)
    def sub (self): #从栈顶弹出两个数，相减，结果压入栈顶，如果不足两个元素则异常
        if (len(self.stack) < 2):
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        res = (a - b) % (2**256)
        self.stack.append(res)
        
    def div (self): #从栈顶弹出两个数，相除，结果压入栈顶，如果不足两个元素则异常 #如果第二个元素（除数）为0，则将0推入堆栈。
        if (len(self.stack) < 2):
            raise Exception("Stack underflow")
        a = self.stack.pop() # 第一个元素为被除数
        b = self.stack.pop() # 第二个元素为除数
        res = a//b % (2**256) if b!=0 else 0
        self.stack.append(res)
    def sdiv (self): #从栈顶弹出两个数，相除，结果压入栈顶，如果不足两个元素则异常 #如果第二个元素（除数）为0，则将0推入堆栈。
        # 比如-1表示为0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 因为 +1 为0
        if (len(self.stack) < 2):
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        res = a//b % (2**256) if b!=0 else 0
        self.stack.append(res)  
    def mod (self):#取模指令。这个指令会从堆栈中弹出两个元素，然后将第一个元素除以第二个元素的余数推入堆栈。如果第二个元素（除数）为0，结果为0。它的操作码是0x06，gas消耗为5
        if (len(self.stack) < 2):
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        res = a % b if b != 0 else 0
        self.stack.append(res)
    def smod (self): #SMOD: 带符号的取模指令。这个指令会从堆栈中弹出两个元素，然后将第一个元素除以第二个元素的余数推入堆栈，结果带符号。如果第一个元素（除数）为0，结果为0。它的操作码是0x07，gas消耗为5。
        if (len(self.stack) < 2):
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        res = a % b if b != 0 else 0
        self.stack.append(res)
    def addmod (self): #ADDMOD: 模加指令。这个指令会从堆栈中弹出三个元素，然后将前两个元素相加，再对第三个元素取模，最后将结果推入堆栈。如果第三个元素（模数）为0，结果为0。它的操作码是0x08，gas消耗为8。
        if (len(self.stack) < 3):
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        n = self.stack.pop()
        res= (a+b)%c if n!=0 else 0
        self.stack.append(res)
    def mulmod (self): #MULMOD: 模乘指令。这个指令会从堆栈中弹出三个元素，然后将前两个元素相乘，再对第三个元素取模，最后将结果推入堆栈。如果第三个元素（模数）为0，结果为0。它的操作码是0x09，gas消耗为8。
        if (len(self.stack) < 3):
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        n = self.stack.pop()
        res = (a*b)%n if n!=0 else 0
        self.stack.append(res)
    def exp(self):
        if (len(self.stack) < 2):
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        res = pow(a,b) % (2**256)
        self.stack.append(res)

    def signextend(self): #SIGNEXTEND指令会从堆栈中弹出两个元素，对第二个元素进行符号扩展，扩展的位数由第一个元素决定，然后将结果推入堆栈。它的操作码是0x0B，gas消耗为5。
        if (len(self.stack) < 2):
            raise Exception("Stack underflow")
        b = self.stack.pop()
        x = self.stack.pop()
        if b < 32: # b大于32不能扩展
            sign_bit = 1<< (8*b - 1) # b 字节的最高位（符号位）对应的掩码值，将用来检测 x 的符号位是否为1
            x = x & ((1 << (8 * b)) - 1)  # 对 x 进行掩码操作，保留 x 的前 b+1 字节的值，其余字节全部置0
            if x & sign_bit:  # 检查 x 的符号位是否为1
                 x = x | ~((1 << (8 * b)) - 1)  # 将 x 的剩余部分全部置1
        self.stack.append(x)
    def lt(self): #LT:LT指令从堆栈中弹出两个元素，比较第二个元素是否小于第一个元素。如果是，那么将1推入堆栈，否则将0推入堆栈。如果堆栈元素不足两个，那么会抛出异常。这个指令的操作码是0x10，gas消耗为3。
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a= self.stack.pop() # 第一个元素
        b = self.stack.pop()# 第二个元素
        self.stack.append(int(b<a))
    def gt (self): #GT: 大于指令。第二个元素是否大于第一个元素
       if len(self.stack) < 2:
            raise Exception("Stack underflow")
       a = self.stack.pop()
       b = self.stack.pop()
       self.stack.append(int(b>a))
    def eq (self): #EQ: 等于指令。第二个元素是否等于第一个元素
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(int(b==a))
    def iszero(self):
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        self.stack.append(int(a==0))
    def slt (self): #SLT: 带符号的小于指令
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(int(b<a)) # naive evm stack 已经是有符号的整数存储了，所以和lt一样实现
    def sgt (self): #SGT: 带符号的大于指令
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(int(b>a)) # naive evm stack 已经是有符号的整数存储了，所以和gt一样实现
    def and_op (self):
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(a&b)
    def or_op (self):
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(a|b)
    def xor_op (self):
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(a^b)
    def not_op (self):
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        self.stack.append(~a % (2**256)) ## 按位非操作的结果需要模2^256，防止溢出
    def shl (self):  #x << y  x左移y位
        #SHL指令执行左移位操作，从堆栈中弹出两个元素，将第二个元素左移第一个元素位数，然后将结果推回栈顶。
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        shift = self.stack.pop() 
        value = self.stack.pop() #移动的位数
        self.stack.append((value<<shift) % (2**256)) # 需要括号保证优先级
    def shr (self): #SHR指令执行右移位操作，从堆栈中弹出两个元素，将第二个元素右移第一个元素位数，然后将结果推回栈顶。
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        shift = self.stack.pop() 
        value = self.stack.pop()
        self.stack.append((value>>shift) % (2**256))
    def byte_op(self): #它的主要作用是从一个256位（32字节）的整数中提取特定位置的字节。具体来说，它从栈中弹出两个元素，一个是要提取字节的位置（position），另一个是源整数（value）。然后，根据位置，它提取出相应的字节并将这个字节的值压回栈顶。
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        position = self.stack.pop()
        value = self.stack.pop()
        if position >= 32:
           res = 0
        else:
            res = (value >> (8*position)) % 256
        self.stack.append(res)     
    def sar(self):
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        a = self.stack.pop()
        b = self.stack.pop()
        self.stack.append(b >> a) # 右移位操作
        
    def mstore(self):
        #MSTORE指令用于将一个256位（32字节）的值存储到内存中。它从堆栈中弹出两个元素，第一个元素为内存的地址（偏移量 offset），
        # 第二个元素为存储的值（value）。操作码是0x52，gas消耗根据实际内存使用情况计算（3+X）
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        value = self.stack.pop()
        while len(self.memory) < offset + 32:
            self.memory.append(0) #内存扩展 添加一个byte的0在这里 + gas消耗
        self.memory[offset:offset+32] = value.to_bytes(32,"big") #将value的32个字节写入内存的offset位置
        
    def mstore8(self): #MSTORE8指令用于将一个8位（1字节）的值存储到内存中。与MSTORE类似，但只使用最低8位。操作码是0x53，gas消耗根据实际内存使用情况计算（3+X）。
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        value = self.stack.pop()
        while len(self.memory) < offset + 32:
            self.memory.append(0)
        self.memory[offset] = value & 0xff # 取低8位 11111111
    def mload(self):
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        while len(self.memory) < offset + 32:
            self.memory.append(0) #内存扩展 添加一个byte的0在这里 + gas消耗
        value = int.from_bytes(self.memory[offset:offset+32],"big")
        self.stack.append(value)
    def mszie(self):
        self.stack.append(len(self.memory))
    def sstore (self):
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        key = self.stack.pop()
        value = self.stack.pop()
        self.storage[key] = value
    def sload(self):
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        key = self.stack.pop()
        value = self.storage.get(key,0)
        self.stack.append(value)
    def findValidJumpDestinations(self): # 这里需要改
         pc=0
         while pc < len(self.code):
             op = self.code[pc] #
             if op == JUMPDEST: # 查看op是不是0x5b 但是要注意这也可能是push进去的value
                 self.validJumpDest[pc] = True
             elif PUSH1 <= op <= PUSH32:# 解决0x5b是push进去的value的问题 如果当前指令是 PUSH 类型，
                 #这行代码将 pc 向前移动到 PUSH 指令后面的数据的末尾。这是因为 PUSH 指令后面紧跟着的是要推送的数据，
                 # 其长度取决于 PUSH 指令的类型（例如，PUSH1 后面跟着 1 个字节的数据，PUSH2 后面跟着 2 个字节，依此类推）。
                 pc += op - PUSH1 + 1 
             pc += 1
    def jumpdest(self): #这里需要改
        pass
    
    def jump(self): #这里需要改 JUMP指令用于无条件跳转到一个新的程序计数器位置。它从堆栈中弹出一个元素，将这个元素设定为新的程序计数器（pc）的值
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        dest = self.stack.pop()
        if dest not in self.validJumpDest: 
            raise Exception("Invalid jump destination")
        else:
            self.pc = dest
    def jumpi(self): 
        if len(self.stack) < 2:
            raise Exception("Stack underflow")
        dest = self.stack.pop() 
        cond = self.stack.pop()
        if cond != 0:
            if dest not in self.validJumpDest:
                raise Exception("Invalid jump destination")
            else:
                self.pc = dest
    def pc(self):
        self.stack.append(self.pc)
    def blockhash(self): ##BLOCKHASH指令用于获取指定区块的哈希值。它从堆栈中弹出一个元素，这个元素是区块的高度（block number），然后将区块的哈希值推入堆栈。如果区块不存在(256区块意外)，那么将0推入堆栈。它的操作码是0x40，gas消耗为20。
        if len(self.stack) < 1:
            raise Exception('Stack underflow')
        number = self.stack.pop() ##堆栈中弹出一个值作为区块高度（block number)
        # 在真实场景中, 你会需要访问历史的区块hash
        if number == self.current_block["number"]:#这里简化只看自己
            self.stack.append(self.current_block["blockhash"])
        else:
            self.stack.append(0)  # 如果不是当前块，返回0
            
    def coinbase (self): #将当前区块的coinbase（矿工/受益人）地址压入堆栈，它的操作码为0x41，gas消耗为2
       self.stack.append(self.current_block["coinbase"])
    
    def timestamp (self): #将当前区块的时间戳压入堆栈，它的操作码为0x42，gas消耗为2
        self.stack.append(self.current_block["timestamp"])
    def number (self): #将当前区块的高度（从创世0向后数的高度）压入堆栈，它的操作码为0x43，gas消耗为2
        self.stack.append(self.current_block["number"])
    def prevrandao (self): #将前一个区块的随机数种子（prevrandao）压入堆栈，它的操作码为0x44，gas消耗为2
        self.stack.append(self.current_block["prevrandao"])
    def gaslimit (self): #将当前区块的gas限制（gaslimit）压入堆栈，它的操作码为0x45，gas消耗为2
        self.stack.append(self.current_block["gaslimit"])
    def chainid (self): #，用于区分不同的区块链网络。在以太坊及其分叉版本中，链ID尤其重要，因为它有助于确保交易只在指定的区块链上有效，从而避免了交易在多个网络上重放（Replay Attack）的风险。
        self.stack.append(self.current_block["chainid"])
    def selfbalance (self): #将当前执行环境或合约的余额压入堆栈，它的操作码为0x47，gas消耗为5
        self.stack.append(self.current_block["selfbalance"])
    def basefee (self): #将当前区块的基础费用（basefee）压入堆栈，它的操作码为0x48，gas消耗为2
        self.stack.append(self.current_block["basefee"])
    def dup (self,position): #（Duplicate）堆栈上的指定元素（根据指令的序号）到堆栈顶部。例如，DUP1复制栈顶元素，DUP2复制距离栈顶的第二个元素，以此类推
        if len(self.stack) < position:
            raise Exception("Stack underflow")
        value = self.stack[-position] # 倒数第几个元素 -1就是最后一个元素 倒数第一个元素是栈顶元素
        self.stack.append(value)
    def swap (self,position): #（Swap）堆栈上的指定元素（根据指令的序号）和栈顶元素交换。例如，SWAP1交换栈顶元素和距离栈顶的第二个元素，SWAP2交换栈顶元素和距离栈顶的第三个元素，以此类推。
        if len(self.stack) < position:
            raise Exception("Stack underflow")
        idx1, idx2 = -1, -position - 1
        self.stack[idx1], self.stack[idx2] = self.stack[idx2], self.stack[idx1]
        
    def sha3 (self):
        if len (self.stack) < 2:
            raise Exception("Stack underflow")
        offset = self.stack.pop()
        size = self.stack.pop()
        while len(self.memory) < offset + size: #新加的 这里可能有错 具体扩展大小是+32还是？需要再次思考
            self.memory.append(0) #内存扩展 添加一个byte的0在这里 + gas消耗
        data = self.memory[offset:offset+size] # 
        
        hash_value = int.from_bytes(sha3.keccak_256(data).digest(), 'big')  # 计算哈希值
        self.stack.append(hash_value)
    def balance (self): #BALANCE 指令用于返回某个账户的余额。它从堆栈中弹出一个地址，然后查询该地址的余额并压入堆栈
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        addr_int = self.stack.pop()
        # 将stack中的int转换为bytes，然后再转换为十六进制字符串，用于在账户数据库中查询
        add_hex_str = '0x' + addr_int.to_bytes(20, byteorder='big').hex()
        self.stack.append(account_db[add_hex_str]['balance'])
        if add_hex_str not in self.warm_address:
            self.warm_address.add(add_hex_str)
            print('cold -> warm address', add_hex_str)
            self.gas += 2600
        else:
            print('warm address', add_hex_str)
            self.gas += 100
    def extcodesize(self): #指令用于返回某个账户的代码长度（以字节为单位）。它从堆栈中弹出一个地址，然后查询该地址的代码长度并压入堆栈。#如果账户不存在或没有代码，返回0。他的操作码为0x3B，gas为2600（cold address）或100（warm address）。
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        addr_int = self.stack.pop()
        # 将stack中的int转换为bytes，然后再转换为十六进制字符串，用于在账户数据库中查询
        addr_str = '0x' + addr_int.to_bytes(20, byteorder='big').hex()
        self.stack.append(len(account_db.get(addr_str, {}).get('code', b''))) # 找不到返回一个空的字典 因为是长度为单位，找不到返回0
        if addr_str not in self.warm_address:
            self.warm_address.add(addr_str)
            print('cold -> warm address', addr_str)
            self.gas += 2600
        else:
            print('warm address', addr_str)
            self.gas += 100    
    def extcodecopy(self): #指令用于将某个账户的部分代码复制到EVM的内存中 #gas 没有添加
        if len(self.stack) < 4:
            raise Exception("Stack underflow")
        addr_int= self.stack.pop()
        mem_offset = self.stack.pop()
        code_offset = self.stack.pop()
        length = self.stack.pop()
        addr_str = '0x' + addr_int.to_bytes(20, byteorder='big').hex()
        code = account_db.get(addr_str, {}).get('code', b'')[code_offset:code_offset+length]
        while len(self.memory) < mem_offset + length:
            self.memory.append(0)
        #pdb.set_trace()
        self.memory[mem_offset:mem_offset+length] = code
    def extcodehash(self):#EXTCODEHASH 它从堆栈中弹出一个地址，然后查询该地址的代码并且求代码的哈希并压入堆栈
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        addr_int = self.stack.pop()
        # # 将stack中的int转换为bytes，然后再转换为十六进制字符串，用于在账户数据库中查询
        addr_str = '0x' + addr_int.to_bytes(20, byteorder='big').hex()
        code = account_db.get(addr_str, {}).get('code', b'')
        code_hash = int.from_bytes(sha3.keccak_256(code).digest(), 'big')# 计算哈希值
        self.stack.append(code_hash)
    def address(self): #将当前执行合约的地址压入堆栈。
        self.stack.append(self.txn.thisAddr)
    def origin(self): #将交易的原始发送者EOA（即签名者）地址压入堆栈。
        self.stack.append(self.txn.origin)
    def caller (self): #将当前执行环境的调用者地址压入堆栈。
        self.stack.append(self.txn.caller)
    def callvalue(self):
        self.stack.append(self.txn.value)
    def calldataload(self):#功能：从交易或合约调用的data字段加载数据。它从堆栈中弹出calldata的偏移量（offset），然后从calldata的offset位置读取32字节的数据并压入堆栈。如果calldata剩余不足32字节，则补0。
        if len(self.stack) < 1:
            raise Exception("Stack underflow")
        offset = self.stack.pop() #
        # 从字符串转化成bytes数组
        calldata_bytes = bytes.fromhex(self.txn.data[2:])  # 假设由 '0x' 开头
        data = bytearray(32) # 创建32字节的 byte 数组 每一个都是0 bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        for i in range(32):
            if offset + i < len(calldata_bytes):
                data[i] = calldata_bytes[offset + i]
        self.stack.append(int.from_bytes(data, 'big'))
        
    def calldatasize(self): #功能：返回交易或合约调用的data字段的长度（以字节为单位）。它将data字段的长度压入堆栈。
        # Assuming calldata is a hex string with a '0x' prefix
        size = (len(self.txn.data) - 2) // 2 # 除去0x 每两个十六进制字符表示一个字节的数据 再除以2
        self.stack.append(size)
        
    def calldatacopy(self): #将data中的数据复制到内存中
        if len(self.stack) < 3:
            raise Exception("Stack underflow")
        memo_offset = self.stack.pop()
        calldata_offset = self.stack.pop()
        length = self.stack.pop()
        # 拓展内存用这种形式方便gas计算
        while len(self.memory) < memo_offset + length:
            self.memory.append(0)
        # 从字符串转化成bytes数组
        calldata_bytes = bytes.fromhex(self.txn.data[2:])  # 假设由 '0x' 开头
        # 从calldata复制进内存
        for i in range(length):
            if calldata_offset + i < len(calldata_bytes):
                self.memory[memo_offset + i] = calldata_bytes[calldata_offset + i]
    def codesize(self): #返回当前合约的代码大小（以字节为单位）。它将代码大小压入堆栈。
        addr = self.txn.thisAddr
        self.stack.append(len(account_db.get(addr, {}).get('code', b'')))
        
    def codecopy(self): #当合约需要读取自己的部分字节码时使用这里可能要出问题计算gas的时候
        if len(self.stack) < 3:
            raise Exception("Stack underflow")
        mem_offset = self.stack.pop()
        code_offset = self.stack.pop()
        length = self.stack.pop()
        #获取当前地址的code
        addr = self.txn.thisAddr
        code = account_db.get(addr, {}).get('code', b'')
        # 拓展内存用这种形式方便gas计算
        while len(self.memory) < mem_offset + length:
            self.memory.append(0)
        #代码复制进内存
        for i in range(length):
            if code_offset + i < len(code):
                self.memory[mem_offset + i] = code[code_offset + i]
        
    def gasprice (self): #将当前交易的gas价格压入堆栈。
        self.stack.append(self.txn.gasPrice)
        
    def evm_log(self,num_topics): #将当前交易的日志列表压入堆栈。 gas = 375 + 375 * topic数量 + 内存扩展成本
        #Log指令从堆栈中弹出2 + n的元素。其中前两个参数是内存开始位置mem_offset和数据长度length，n是主题的数量（取决于具体的LOG指令）。所以对于LOG1，我们会从堆栈中弹出3个元素：
        # 内存开始位置，数据长度，和一个主题。需要mem_offset的原因是日志的数据（data）部分存储在内存中，gas消耗低，而主题（topic）部分直接存储在堆栈上。
        if len(self.stack) < 2 + num_topics:
            raise Exception("Stack underflow")
        mem_offset = self.stack.pop()
        length = self.stack.pop()
        topics=[self.stack.pop() for _ in range(num_topics)]
        
        while len(self.memory) < mem_offset + length: #新加的 这里可能有错 具体扩展大小是+32还是？需要再次思考
            self.memory.append(0)
            
        data = self.memory[mem_offset:mem_offset+length]
        log_entry = {
            "address": self.txn.thisAddr,
            "data": data.hex(),
            "topics": [f"0x{topic:064x}" for topic in topics]
        }
        self.logs.append(log_entry)
    
    def run (self):
        self.findValidJumpDestinations()
        while self.pc < len(self.code):
            op = self.next_instruction()
            if PUSH1 <= op <= PUSH32:
                size = op - PUSH1 + 1
                self.push(size)
            elif op  ==  PUSH0:
                self.stack.append(0)
            elif op == POP:
                self.pop()
            elif op == ADD:
                self.add()
            elif op == MUL:
                self.mul()
            elif op == SUB: 
                self.sub()
            elif op == DIV:
                self.div()
            elif op == SDIV:
                self.sdiv()
            elif op == MOD:
                self.mod()
            elif op == SMOD:
                self.smod()
            elif op == ADDMOD:
                self.addmod()
            elif op == MULMOD:
                self.mulmod()
            elif op == EXP:
                self.exp()
            elif op == SIGNEXTEND:
                self.signextend()
            elif op == LT:
                self.lt()
            elif op == GT:
                self.gt()
            elif op == EQ:
                self.eq()
            elif op == ISZERO:
                self.iszero()
            elif op == SLT:
                self.slt()
            elif op == SGT:
                self.sgt()
            elif op == AND:
                self.and_op()
            elif op == OR:
                self.or_op()
            elif op == XOR:
                self.xor_op()
            elif op == NOT:
                self.not_op()
            elif op == SHL:
                self.shl()
            elif op == SHR:
                self.shr()
            elif op == BYTE:
                self.byte_op()
            elif op == SAR:
                self.sar()
            elif op == MSTORE:
                self.mstore()
            elif op == MSTORE8:
                self.mstore8()
            elif op == MLOAD:
                self.mload()
            elif op == MSIZE:
                self.mszie()
            elif op == SSTORE:
                self.sstore()
            elif op == SLOAD:
                self.sload()
            elif op == STOP:
                 print('Program has been stopped')
                 break
            elif op == JUMP:
                self.jump()
            elif op == JUMPDEST: 
                self.jumpdest()
            elif op == JUMPI:
                self.jumpi()
            elif op == PC:
                self.pc()
            elif op == BLOCKHASH:
                self.blockhash()
            elif op == COINBASE:
                self.coinbase()
            elif op == TIMESTAMP:
                self.timestamp()
            elif op == NUMBER:
                self.number()
            elif op == PREVRANDAO:
                self.prevrandao()
            elif op == GASLIMIT:
                self.gaslimit()
            elif op == CHAINID:
                self.chainid()
            elif op == SELFBALANCE:
                self.selfbalance()
            elif op == BASEFEE:
                self.basefee()
            elif DUP1 <= op <= DUP16:
                position = op - DUP1 + 1
                self.dup(position)
            elif SWAP1 <= op <= SWAP16: # 如果是SWAP1-SWAP16
                position = op - SWAP1 + 1
                self.swap(position)
            elif op == SHA3:
                pdb.set_trace()
                self.sha3()
            elif op == BALANCE:
                self.balance()
            elif op == EXTCODESIZE:
                self.extcodesize()
            elif op == EXTCODECOPY:
                self.extcodecopy()
            elif op == EXTCODEHASH:
                self.extcodehash()
            elif op == ADDRESS:
                self.address()
            elif op == CALLDATALOAD:
                self.calldataload()
            elif op == CALLDATASIZE:
                self.calldatasize()
            elif op == CALLDATACOPY:
                self.calldatacopy()
            elif op == CODESIZE:
                self.codesize()
            elif op == CODECOPY:
                self.codecopy()
            elif op == GASPRICE:
                self.gasprice()
            elif op == LOG0:
                self.evm_log(0)
            elif op == LOG1:
                self.evm_log(1)
            elif op == LOG2:
                self.evm_log(2)
            elif op == LOG3:
                self.evm_log(3)
            elif op == LOG4:
                self.evm_log(4)
            else:
                raise Exception("Invalid opcode")
if __name__ == "__main__":
    addr = '0x9bbfed6889322e016e0a02ee459d306fc19545d8'
    txn = Transaction(to=addr, value=10, data='0x9059cbb20000000000000000000000009bbfed6889322e016e0a02ee459d306fc19545d80000000000000000000000000000000000000000000000000000000000000001', 
                  caller=addr, origin=addr, thisAddr=addr)

    #code = b"\x60\x01\x60\x01" #push test
    #code = b"\x60\x01\x60\x01\x50" #push pop test    
    #code = b"\x60\x02\x60\x03\x01" # add test
    #code = b"\x60\x02\x60\x03\x02" # mul test
    #code = b"\x60\x02\x60\x03\x03" # sub test   
    #code = b"\x60\x03\x60\x06\x04" # div test
    #code = b"\x60\xff\x60\x05\x05" # sdiv test -1/5 = 0
    #code = b"\x60\x02\x60\x03\x10" # lt test
    #code = b"\x60\x02\x60\x03\x11" # gt test
    #code = b"\x60\x02\x60\x03\x14" # eq test
    #code = b"\x60\x00\x15" # iszero test
    #code = b"\x60\xff\x60\xff\x12" # slt test
    #code = b"\x60\xff\x60\xff\x13" # sgt test
   # code = b"\x60\x02\x60\x03\x16" # and test
    # code = b"\x60\x02\x60\x03\x17"
    #code = b"\x60\x02\x19" # not test
    #code = b"\x60\x02\x60\x03\x1B" 
    #code = b"\x60\x10\x60\x03\x1C"
    #code = b"\x60\x02\x60\x20\x52" # mstore test
    #code = b"\x60\x02\x60\x20\x53" # mstore8 test
    #code = b"\x60\x02\x60\x20\x52\x59" # msize test 64  说明自动补0正常
    #code = b"\x60\x02\x60\x00\x55" # sstore test
    #code = b"\x60\x02\x60\x00\x55\x60\x00\x54" # sload test
    #code = b"\x00" # stop test
    #code = b"\x60\x04\x56\x00\x5b" # jump test 没用中断说明跳到了0-index的4号位置 
    #code = b"\x60\x01\x60\x06\x57\x00\x5b" # jumpi test
    #code =  b"\x60\x04\x56\x60\x5b\x60\xff" # in·valid jump destination test
    #code = b"\x46"

    #code = b"\x43\x40" # blockhash test
    #code = b"\x60\x01\x60\x02\x80" # dup1 test
    #code = b"\x60\x01\x60\x02\x90" # swap1 test
    #code = b"\x5F\x5F\x20" # sha3 test #push0 push0 sha3
    # bytecode = b"\x60\x01\x60\x01\x20"
    #code = b"\x73\x9b\xbf\xed\x68\x89\x32\x2e\x01\x6e\x0a\x02\xee\x45\x9d\x30\x6f\xc1\x95\x45\xd8\x31" #USH20 9bbfed6889322e016e0a02ee459d306fc19545d8 BALANCE）。这个字节码使用PUSH20将一个地址推入堆栈，然后使用BALANCE指令查询该地址的余额。
    # BALANCE
    #code = b"\x73\x9b\xbf\xed\x68\x89\x32\x2e\x01\x6e\x0a\x02\xee\x45\x9d\x30\x6f\xc1\x95\x45\xd8\x3B"
    #code = b"\x60\x04\x5F\x5F\x73\x9b\xbf\xed\x68\x89\x32\x2e\x01\x6e\x0a\x02\xee\x45\x9d\x30\x6f\xc1\x95\x45\xd8\x3C"
    #code = b"\x73\x9b\xbf\xed\x68\x89\x32\x2e\x01\x6e\x0a\x02\xee\x45\x9d\x30\x6f\xc1\x95\x45\xd8\x3F"
    # ADDRESS
    #code = b"\x30"
    #evm = EVM(code, txn)
    #evm.run()
    #print(evm.stack)
    # CALLDATALOAD
    code = b"\x60\x04\x35"
    evm = EVM(code, txn)
    evm.run()
    print(evm.stack)
    print(hex(evm.stack[-1]))
    # output: 0x9bbfed6889322e016e0a02ee459d306fc19545d8
    # CALLDATASIZE
    # CALLDATASIZE
    code = b"\x36"
    evm = EVM(code, txn)
    evm.run()
    print(evm.stack)
   # output: 68 (4+32+32)
    # CALLDATACOPY
    code = b"\x60\x04\x5F\x5F\x37"
    evm = EVM(code, txn)
    evm.run()
    print(evm.memory.hex())
    # code size
    code = b"\x38"
    evm = EVM(code, txn)
    evm.run()
    print(evm.stack)
    # output: 4
    code = b"\x60\x04\x5F\x5F\x39" # codecopy
    evm = EVM(code, txn)
    evm.run()
    print(evm.memory.hex())

    # GASPRICE
    code = b"\x3A"
    evm = EVM(code, txn)
    evm.run()
    print(evm.stack) #1X
    # LOG0
    code = b"\x60\xaa\x60\x00\x52\x60\x01\x60\x1f\xa0"
    evm = EVM(code, txn)
    evm.run()
    print(evm.logs)
    
    #LOG1
    code = b"\x60\xaa\x60\x00\x52\x60\x11\x60\x01\x60\x1f\xa1"
    evm = EVM(code, txn)
    evm.run()
    print(evm.logs)
    # output: [{'address': '0x9bbfed6889322e016e0a02ee459d306fc19545d8', 'data': 'aa', 'topics': ['0x00000000000000000000000000000000000000000000

    #print(evm.stack)  
    #print(hex(evm.stack[-1]))
