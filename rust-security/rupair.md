#  Papers

<!-- 每个小节中的文献按照发表年排列；同一年发表的，按照第一作者名字排序 --> 

##  智能合约的自动修复



<ol>
    <li>
2020，SANER，<a href="https://siqima.me/publications/saner20a.pdf">SmartShield: Automatic Smart Contract Protection Made Easy.</a>
<br><br>
提出了一个字节码纠正系统SMARTSHIELD，以自动修复智能合约中三个典型的安全相关错误：即调用外部合约后本合约状态发生改变（可导致重放攻击）、缺少对算数运算的越界检查（可导致整数溢出）和缺少对调用外部合约失败的结果检查。
</li>
<br><br>   
    <li>
2020，ACM Trans. Softw. Eng. Methodol., Vol. 1, No. 1，<a href="https://arxiv.org/pdf/1912.05823.pdf">Smart Contract Repair.</a>
<br><br>
开发了一个完全自动化的智能合约修复工具SCRepair，并提出了第一个基于搜索的自动化智能合约修复算法。该工具与强大的智能合约安全分析器Oyente和Slither集成在一起，可以检测和修复智能合约中的安全漏洞。</li>
</ol>




##  源代码级修复

<ol>
<li> 2007, Proceedings of the 2nd ACM symposium
on Information, computer and communications security. <a href="https://dl.acm.org/doi/abs/10.1145/1229285.1267001">Autopag: towards
automated software patch generation with source code root cause
identification and repair.</a>
<br><br>
提出了AutoPaG，该工具能够处理越界漏洞。
AutoPaG能动态捕捉越界违规，然后针对数据流分析，自动分析程序源代码并定位到有漏洞的源代码语句。接着AutoPaG会生成一个源代码补丁，在没有任何人工干预的情况下临时修复它。并用Wilander缓冲区溢出基准测试套件以及5个现实世界的越界漏洞对AutoPaG进行了评估，进一步证实了它的有效性和实用性。
</li>
<br><br>
<li> 2010, European Symposium on Research in Computer Security. <a href="https://link.springer.com/chapter/10.1007/978-3-642-15497-3_5">Intpatch: Automatically fix integer-overflow-to-buffer-overflow vulnerability at compiletime</a>
<br><br>提出了IntPatch,一个能够识别潜在的IO2BO（Integer-Overflow-to-Buffer-Overflow ）漏洞并自动修复它们的工具。该工具利用经典的类型理论和数据流分析框架来识别潜在的IO2BO漏洞，通过插入动态的检查代码来防止该漏洞。并在许多开源应用中评估了IntPatch，实验表明，IntPatch已经捕获了测试套件中所有46个已知的IO2BO漏洞，并发现了21个新漏洞，由IntPatch修补的应用程序的运行时性能损失可以忽略不计，平均约为1%。
    </li>
<br><br>
    <li> 2012, ” Ieee transactions on software engineering. <a href="https://ieeexplore.ieee.org/abstract/document/6035728">Genprog: A
generic method for automatic software repair</a>
<br><br>描述了一种用于遗留程序中缺陷的自动修复技术，GenProg，使用扩展的基因编程形势开发程序变体，使用测试套件编码程序缺陷和功能，并使用结构差分算法和增量调试减少了变体与原始程序之间的区别以最小化修复。</li>
<br><br>
    <li> 2016, ASE. <a href="https://dl.acm.org/doi/abs/10.1145/2970276.2970282">Bovinspector: automatic inspection and
repair of buffer overflow vulnerabilities</a>
<br><br>提出了BovInspector，一个用于自动静态缓冲区溢出检查和修复的工具框架。该工具结合静态分析和动态符号执行技术来自动检查缓冲区溢出，并使用三种预定义的策略进行修复（添加边界检查、替换更安全的API、扩展缓冲区）。</li>
<br><br>
    <li> 2017, European Symposium on Research in Computer Security. <a href="https://link.springer.com/chapter/10.1007/978-3-319-66399-9_13">Vurle: Automatic
vulnerability detection and repair by learning from examples</a>
<br><br>
提出了VuRLE，该工具使用上下文模式来检测漏洞，并支持定制相应的编辑模式来修复漏洞。
</li>
<br><br>
    <li>
    2017, ESEC/SIGSOFT FSE 2017, <a href = "https://dl.acm.org/doi/10.1145/3106237.3106253">Automatic inference of code transforms for patch generation.</a>
<br><br>        
提出从实际Java项目中的缺陷和补丁代码，自动推断补丁生成变换或候选补丁搜索空间的系统。通过捕获不同应用程序中原始程序AST转换为修补程序AST的公共模式，实现模式匹配。通过生成器系统生成候选补丁代码。
    </li>
<br><br>
 <li>
    2018, ASE, <a href="https://dblp.org/pid/02/320.html">An Empirical Investigation into Learning Bug-Fixing Patches in the Wild via Neural Machine Translation.</a>
     <br><br>
从Github中挖掘bug修复commit，抽象出错误代码和对应的修复代码，使用细粒度源代码差异提取方法级AST编辑操作，基于神经机器翻译训练生成编解码模型。
    </li>
<br><br>
    <li>
    2019，Sci. China Inf. Sci. 62(10)，<a href = "https://link.springer.com/article/10.1007%2Fs11432-018-1465-6">A manual inspection of Defects4J bugs and its implications for automatic program repair.</a>
        <br><br>
手动分析Defects4j中实际漏洞，分析比较现有的程序自动修复技术，并总结了七种故障定位和七种补丁生成策略，指出程序自动修复技术未来改进方向。
    </li>
<br><br>
 <li>
    2019,  ISSRE, <a href = "https://ieeexplore.ieee.org/document/8987548">Analyzing the Context of Bug-Fixing Changes in the OpenStack Cloud Computing Platform.</a>
     <br><br>
对三个OpenStack项目中的bug修复进行深入的实证分析，使用修复代码的抽象语法树（AST）的数字特征对错误修复进行聚类分析，并关注修复代码上下文以此缩小程序搜索空间，提高错误定位和代码修复的能力。
    </li>
<br><br>
 <li>
    2020, SAC, <a href = "https://dl.acm.org/doi/10.1145/3341105.3373880">How Bugs Are Fixed: Exposing Bug-fix Patterns with Edits and Nesting Levels.</a>
     <br><br>
对5个软件系统的超过4653个错误修订进行定量和定性分析，确定了38种bug修复编辑模式和37种新的嵌套代码结构模式。
    </li>
<br><br>
</ol>














##  二进制级修复

<ol>
<li>
2014, NDSS，<a href="https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.715.7897&rep=rep1&type=pdf">Appsealer: automatic generation of vulnerabilityspecific patches for preventing component hijacking attacks in android
applications</a>
<br><br>

</li>
<br><br>



<li>
2014，ASE，<a href="https://dl.acm.org/doi/abs/10.1145/2642937.2642955">Towards self-healing
smartphone software via automated patching</a>
<br><br>
。。。
</li>
<br><br>

<li>
2016，AsiaCCS，<a href="https://dl.acm.org/doi/abs/10.1145/2897845.2897896">Cdrep: Automatic repair of
cryptographic misuses in android applications</a>
<br><br>
提出了CDRep(密码误用检测和修复)，它可以自动检测和修复密码应用程序接口的误用。
</li>
<br><br>

</ol>



​                                        




##  线程安全



1. 2018，[Transactional Memory in Rust](https://dash.harvard.edu/bitstream/handle/1/38811564/LIVELY-SENIORTHESIS-2018.pdf?sequence=3&isAllowed=y)

   描述了sto-rs（将sto移植到rust）的实现，并表明了Rust的类型系统可以用来提高STO的事务安全性。

2. 2019，CORR，[A Practical Analysis of Rust's Concurrency Story](https://arxiv.org/abs/1904.12210)

   开发者们常常通过使用锁来避免数据争用，然而因为锁序列化访问，所以一次只有一个线程可以访问数据，即使这些进程访问的是数据结构的不同部分，这样就会减慢程序运行速度。本文实现了无锁的并发hashmap,成为了Rust语言中最快的并发hashmap之一。并说明了在开发这个无锁并发hashmap时，Rust语言安全特性所产生的帮助和阻碍。

   Aditya Saligrama, Andrew Shen, Jon Gjengset:
   A Practical Analysis of Rust's Concurrency Story. CoRR abs/1904.12210 (2019)

3. 2019,CoRR,[Fearless Concurrency? Understanding Concurrent Programming Safety in Real-World Rust Software](https://arxiv.org/abs/1902.01906)

   本文从两个方面对Rust的并发性进行研究：并发的使用以及Rust中存在的并发bug。

   并发bug分为两种：死锁bug和非死锁bug，其中数据争用bug是一种非常常见的非死锁bug。

   本文针对死锁bug和数据竞争bug进行研究，发现：

   ​	大部分死锁bug都是由双锁导致，其他的则是由误用信道引起。

   ​	对于数据争用bug，在unsafe code中存在，这是由不安全代码中的指令引起的。safe code中也存在数据争用bug，这些bug全都是误用原子操作引起的（因为Rust支持原子类型的共享变量，而且对原子变量进行读写操作会逃过Rust的所有权检查）。

   对未来的启示：传统的并发bug检测和修复技术要把重点放在互斥锁上，解决Rust中的并发bug应该多多关注channel和atomic。由于双锁和信道误用是造成死锁bug的主要原因，所以对于死锁bug的检测，我们可以设计一个静态分析系统，识别函数调用中可能的锁操作，以及根据线程之间的消息传递来推断出线程等待关系。而对于数据争用bug的检测，我们可以重点关注unsafe code以及safe code中的原子操作。

   Zeming Yu, Linhai Song, Yiying Zhang:
   Fearless Concurrency? Understanding Concurrent Programming Safety in Real-World Rust Software. CoRR abs/1902.01906 (2019)

   

4. 2020，Wuhan University Journal of Natural Sciences，[RSMC： A Safety Model Checker for Concurrency and Memory Safety of Rust](http://www.cnki.com.cn/Article/CJFDTotal-WHDZ202002006.htm)

   介绍了RSMC，一个基于SMACK的工具，用于检测Rust程序中的并发错误和内存安全错误。RSMC结合了并发原语模型检查和内存边界	模型检查，它可以通过断言生成器自动将安全属性断言插入到每个Rust程序中，以有效地检测并发安全bug和内存安全bug。实验结果	表明，该工具能够有效地检测Rust程序中的内存与并发bug。但是本文只关注了内存访问并发问题，并未考虑网络并发和文件并发。




​	





   

## 形式化验证



<ol>
<li>
    2015，ASE，<a href="https://ieeexplore.ieee.org/document/7371997">CRUST: A bounded verifier for Rust</a><br><br>
    结合了穷举测试例生成和有界模型检查技术，用于检测 unsafe库代码中的内存错误、以及Rust指针别名的使用是否违反了不变量。CRUST将Rust代码转换为C代码来验证unsafe rust 代码的内存安全性。在真实库代码上的实验表明，CRUST能够发现真实的内存错误。
</li>
 <br><br>
 <li>2015，University of Washington，<a href="https://dada.cs.washington.edu/research/tr/2015/03/UW-CSE-15-03-02.pdf">Patina: A Formalization of the Rust Programming Language</a><br><br>提出了Patina，针对Rust的一个子集，给出了涵盖内存安全、指针和借用语义的形式化语义，描述了借用检查器的操作语义，并形式化了Rust类型系统。</li>
    <br><br>
<li>
2018，TASE，<a href="https://arxiv.org/abs/1804.10806">KRust: A Formal Executable Semantics of Rust</a>
    <br><br>
 本文给出了第一个针对Rust语言的形式化可执行语义KRust（使用了K框架进行语义开发），KRust 目前涵盖了Rust常见的语法和语义，包括了Rust三个核心特性：所有权，借用，生命周期。通过语义对比测试实验发现了Rust编译器的缺陷，另外还介绍了KRust在Rust
程序分析和验证上的潜在应用。
</li>
<br><br>
<li> 2018, POPL, <a href="https://dl.acm.org/doi/10.1145/3158154">RustBelt: securing the foundations of the rust programming language</a>
<br><br>
Rust的安全声明没有得到充分证实，本文提出了RustBelt，一个可扩展的语义方法来证明Rust的安全性。但是并没有证明整个Rust语言，而是形式化了一个Rust的变体λRust（融合了Rust核心特性并采用了一种简化的内存模型），并在Coq中证明了Rust的类型系统可以保证λRust的内存和线性安全。
</li>
<br><br>
<li>2020，ACM，<a href="https://dl.acm.org/doi/10.1145/3371102">RustBelt meets relaxed memory</a>
<br><br>
提出了RustBelt Relaxed，这是对RustBelt研究项目的扩展，并考虑了一致性内存操作的安全性，在此过程中发现了Arc库中的数据竞争。</li>
<br><br>
<li>
2020,POPL,<a href="https://plv.mpi-sws.org/rustbelt/stacked-borrows/paper.pdf">Stacked Borrows: An Aliasing Model for Rust.</a>
<br><br>
    提出了Stacked Borrows ，它可以使编译器用Rust类型的强别名信息来更好地分析和优化其正在编译的代码，并在coq中形式化证明了它的有效性。
</li>
<br><br>
<li>
2018,IEEE,<a href="https://ieeexplore.ieee.org/document/8471992">No panic! verification of rust programs by symbolic execution</a>
<br><br>
Rust编译器在编译时会尽可能地确保内存安全，对于一些特定的情况，Rust编译器会进行运行时检查，但这会降低程序的性能，甚至会导致死机。本文提出了一个解决方案，通过使用KLEE工具符号执行来静态地保证Rust代码的内存安全和无死机执行，并且证明了该方法的可行性。
</li>
<br><br>
 <li>
2019，IEEE，<a href="https://ieeexplore.ieee.org/document/8972014">Verification of Safety Functions Implemented in Rust - a Symbolic Execution based approach</a>
<br><br>
本文研究了如何通过基于断言的方法来验证以Rust语言实现的安全函数，该方法利用了LLVM-KLEE 符号执行引擎。本文还讨论了由符号执行中路径/状态爆炸引起的复杂性问题。该方法的可行性在一个典型的用例（该用例实现了来自PLCopen库的一个安全函数）中得到了证明。
</li>
<br><br>
<li>2018,CORR,<a href="https://arxiv.org/abs/1806.02693">Rust Distilled: An Expressive Tower of Languages.</a>
 <br><br>本文为Rust设计了一个形式语义，该语义在没有生命周期分析细节的情况下能涵盖所有权和借用。这种语义对所有权高级理解进行建模，因此接近源代码级的Rust(但带有完整的类型注释)，不同于最近的RustBelt，Rustelt旨在验证Rust标准库中不安全代码的安全性，但本文将标准库API建模为原语，产生了一个更简单的Rust模型及其类型系统。</li>
<br><br>
<li>
    2016,ETH,<a href="https://www.research-collection.ethz.ch/handle/20.500.11850/155723">Rust2Viper: building a static verifier for rust.</a>
 <br><br>介绍了Rust2Viper（rust验证器）的思想和初步实现，它将Rust转换为Sliver代码，然后使用Viper（基于权限的逻辑验证器）进行验证。
    <br>
    Hahn, Florian. Rust2Viper: Building a static verifier for Rust. MS thesis. ETH Zürich, 2016.
</li>
    <br><br>
<li>
    2020,CORR,<a href="https://arxiv.org/abs/2002.09002">RustHorn: CHC-based verification for Rust programs</a>
 <br><br>提出了一种新的基于CHC的程序验证方法，该方法将rust程序指针操作转换为CHC，通过利用所有权来清除指针和堆。并为Rust的一个子集实现了一个原型验证工具，证实了这个方法的有效性。
<br>
Yusuke Matsushita, Takeshi Tsukada, Naoki Kobayashi:
RustHorn: CHC-based Verification for Rust Programs (full version). CoRR abs/2002.09002 (2020)
</li>
     <br><br>
<li>
    2019,OOPSLA,<a href="https://dl.acm.org/doi/10.1145/3360573">Leveraging rust types for modular specification and verification</a>
 <br><br>实现了一种新的验证工具，它利用Rust的类型系统提供的保证大大简化了用Rust编写的系统软件的验证。该技术的一个关键优点是，证明是在不暴露底层逻辑的情况下自动构建和检查的，允许用户只在编程语言的抽象层次上工作。评估表明，该技术可以可靠地自动构建Rust代码的核心证明，并验证函数正确性。
</li>
     <br><br>
<li>
    2018,ATVA,<a href="https://link.springer.com/chapter/10.1007%2F978-3-030-01090-4_32">Verifying Rust Programs with SMACK</a>
 <br><br>目前缺乏针对Rust的自动化软件验证器，本文扩展了SMACK，来支持对Rust的验证，并且描述了如何在SMACK验证器中实现Rust程序的验证。
</li>
         <br><br>
<li>
    2016,<a href="https://pp.ipd.kit.edu/uploads/publikationen/ullrich16masterarbeit.pdf">Simple Verification of Rust Programs via Functional Purification</a>
 <br><br>提出了第一个形式化验证安全Rust代码的通用工具，并成功地用它证明了一个标准算法的正确性和渐近复杂性以及一个数据结构的正确性。该工具通过使用Rust类型系统的特殊保证，将命令式Rust代码转换成纯函数式代码，这是任何其他主要命令式编程语言所没有的。但是它还不能验证Rust程序员日常使用和依赖的大多数的标准算法和数据结构，并且不能验证含有unsafe 的Rust代码。
</li>
          <br><br>
<li>
    2019,<a href="https://etd.adm.unipi.it/t/etd-07092019-130036/">A Formalization of the Static Semantics of Rust</a>
 <br><br>形式化了Rust静态语义（包含生命周期在内）
</li>
</ol>




## 较少价值

1. 2021,PeerJ Computer Science,[Evaluation of Rust code verbosity, understandability and complexity](https://peerj.com/articles/cs-406/)

   本文使用静态度量评估了Rust代码的复杂性和可维护性，并对用C、c++、JavaScript、Python和TypeScript编写的等效代码进行对比。发现：

   Rust的可维护性指标比语法和代码结构与它相似的C和C++略高，并且可以产生更少的冗余，更有组织、更加易读。但是可维护性比更复杂和高级的面向对象语言要低。然而与其他所有语言相比，用Rust语言编写的源代码可理解性最高。

2. 2020，Saarland University，[Understanding and evolving the Rust programming language.](https://publikationen.sulb.uni-saarland.de/handle/20.500.11880/29647)

   本文详细介绍了RustBelt和Stacked Borrows这两个项目，以供读者更好地理解和发展rust语言。

   Ralf Jung:
   Understanding and evolving the Rust programming language. Saarland University, Saarbrücken, Germany, 2020

3. 2019，[Enhancing Forensic-Tool Security with Rust: Development of a String Extraction Utility](https://commons.erau.edu/jdfsl/vol14/iss2/4/)

   开发了一个名为Stringsext的取证工具（是GUN-strings工具的重新实现和增强）。

4. 2008,[Learning from mistakes - A comprehensive study of real world concurrency bug characteristics. ](http://www.cs.columbia.edu/~junfeng/09fa-e6998/papers/concurrency-bugs.pdf)

   本文研究了105个并发bug，包括74个非死锁bug，31个死锁bug，这些bug都是从四个大型且成熟的开源应用程序中随机收集的（MySQL，Apache，Mozilla和OpenOffice，用它们代表服务器和客户端应用程序），主要是研究这些bug的bug 模式，表现形式和修复策略以及bug其他特征，对于每一个bug，都会仔细检查它的bug报告，相应的源代码，相关的补丁以及开发者们的讨论。发现：大约三分之一以的非死锁并发bug都是因为违反顺序或者违反原子性；大约34%的非死锁并发bug涉及并发访问多变量，并且这些bug很难被现有的bug检测工具检测到。对于非死锁bug的修复来说，四分之三都是通过其他技术修复的，而不仅仅是通过添加或者更改锁这么简单。

   本文为并发bug的检测，测试和并发编程设计提供了有用的指导。

5. 2017，[Implementation of the de novo genome assembler in the Rust programming language](https://repo.pw.edu.pl/info/bachelor/WUTcf19ce44565b42cfb459ad2ac64e7af7/?r=diploma&tab=&lang=en)

   本文描述了用Rust编程语言编写的de novo 基因序列汇编器的设计与实现。

6. [一种模块化可拓展策略的模糊测试工具](https://d.wanfangdata.com.cn/periodical/ChlQZXJpb2RpY2FsQ0hJTmV3UzIwMjEwMzAyEg9kenNqZ2MyMDE4MjMwMDUaCDV4Mnp1aG13)

   设计和实现了一种模块化的、可拓展策略的模糊测试工具.我们将整个模糊测试的过程模块化,并将模块分为不可被拓展和可被拓建的模块.对于基础的不可被拓展的模块,我们优化并保证其高性能.我们使用Rust语言实现这些模块,并采用Fork server、CPU核心绑定、高效IPC、虚拟内存文件系统等优化技术.

7. 2018,计算机科学与探索，[KRust:Rust形式化可执行语义](http://fcst.ceaj.org/CN/abstract/abstract2041.shtml)

   提出了针对Rust语言的形式化可执行语义KRust.为了确保语义的可执行性和应用性,使用了K框架进行语义的开发.KRust目前涵盖了Rust常见的语法和语义,包括了Rust的3个核心特性:所有权、借用和生命周期.KRust通过了191个测试样例,其中157个都是来自Rust官方的测试集.语义对比测试实验发现了Rust编译器的缺陷.此外, KRust的语义还可以被应用于开发Rust程序分析工具.

   王丰，张俊. KRust:Rust形式化可执行语义[J]. 计算机科学与探索, 2019, 13(12): 2008-2014.

8. [基于rust编程语言的i2p匿名通信设计](https://d.wanfangdata.com.cn/thesis/ChJUaGVzaXNOZXdTMjAyMTAzMDISCFkzNDQ3Njg3Ggg1eDJ6dWhtdw%3D%3D)

   本文的主要内容包括了匿名通信中的一些基本概念，I2P创建隧道过程，网络数据库工作机制，加强版传输层协议，加密算法，消息数据包的构造及算法实现，传输层协议的握手流程及算法实现，并在最后实现了一个由rust语言写成的I2P网络原型，并分析了其工作流程及存在的问题。

9. 2020，[Compile-Time Reflection in Rust A New Tool for Making Derive Macros](https://www.duo.uio.no/bitstream/handle/10852/80503/1/Master_thesis.pdf)

   本文介绍了一个名为reflect的新库，该库旨在处理过程宏的一些难题。

10. 2018，[Rust: Powered by Ownership](https://maxmeldrum.com/assets/files/rust_report.pdf)

    深入探究Rust语言，并主要关注它的所有权特性。

























