#  Papers

##  安全工具与软件



<ol>
<li>
2020，CCS，<a href="https://dl.acm.org/doi/10.1145/3372297.3420024">VRLifeTime - An IDE Tool to Avoid Concurrency and Memory Bugs in Rust.</a>
<br><br>
Rust中许多bug都是由于程序员误解了Rust的生命周期造成的。本文实现了一个IDE工具（VRLifetime），可以使Rust程序中变量生命周期范围可视化，帮助程序员避免与生命周期相关的bug。此外，VRLifetime还具备检测双锁死锁bug的能力，并提供详细的调试信息，以促进bug的验证以及修复。
</li>
<br><br>   
<li>
2020，CORR，<a href="https://arxiv.org/abs/2011.09012">RustViz: Interactively Visualizing Ownership and Borrowing.</a>
<br><br>
本文介绍了一个工具（RustViz，可以让rust代码中每个变量所有权以及借用事件可视化，以
帮助学习者进一步了解Rust的所有权以及借用规则。
</li>
<br><br>
<li>
2015, ACM,<a href="https://dl.acm.org/doi/10.1145/2818302.2818306">Ownership is theft:Experiences building an embedded os in rust.</a>
<br><br>
给出了用Rust实现嵌入式操作系统的经验。
</li>
<br><br>
<li>
2019，IEEE，<a href="https://ieeexplore.ieee.org/document/8972088/">Cargo-call-stack Static Call-stack Analysis for Rust</a>
<br><br>
提出了一种方法，利用底层LLVM编译器提供的LLVM-IR信息对Rust应用程序进行编译时分析。该方法的可行性已经通过实现
一个开源工具，cargo-call-stack，得到了验证,并且针对ARM Cortex-M 系列微处理器的嵌入式应用进行实验，cargo-call-stack提供了安全且严格的堆栈使用估计。
</li>
<br><br>
<li>
2020，ACM，<a href="https://dl.acm.org/doi/10.1145/3381052.3381326">Intra-unikernel isolation with Intel memory protection keys</a>
<br><br>
用Rust为单内核实例中的组件实现了一个隔离方案（将安全的内核代码与不安全的内核代码隔离，内核代码与用户代码隔离），该方法依靠英特尔MPK技术，可以保持单内核同一地址空间特性，从而保持其性能优势。
</li>
<br><br>
<li>
2016，ICSE，<a href="https://ieeexplore.ieee.org/document/7883291/">Engineering the Servo Web Browser Engine Using Rust</a>
<br><br>
本文用rust编写了Servo网络浏览器引擎，并讨论了现代网络浏览器引擎的设计和架构，展示了rust如何来解决其他浏览器引擎中许多最常见的安全问题和软件工程领域的挑战，并探讨了一些未解决的问题和未来研究的领域。
</li>
 <br><br>
<li>
2020，<a href="https://www.sciencedirect.com/science/article/pii/S1877050920323565">Stuck-me-not: A deadlock detector on blockchain software in Rust</a>
<br><br>
本文分析了用Rust编写的区块链系统中常见的锁相关缺陷，并针对最常见的死锁类型:双锁，提出了第一个基于mir的静态死锁检测器Stuck-me-not。
 </li>
     <br><br>
<li>
2017，CORR,<a href="https://arxiv.org/abs/1702.02951">What can the programming language Rust do for astrophysics?</a>
<br><br>
通过重新实现Mercury-T(该模型是Fortran代码，用于模拟多行星系统的动力学和潮汐演化)的基本部分来探索Rust在天体物理学中的优缺点.
<br>
Sergi Blanco-Cuaresma, Emeline Bolmont:
What can the programming language Rust do for astrophysics? CoRR abs/1702.02951 (2017)
 </li>
     <br><br>
<li>
2019，<a href="http://dspace.iiti.ac.in:8080/xmlui/handle/123456789/2069">Implementing realtime kernel in rust programming language</a>
<br><br>
用rust语言实现实时内核
 </li>
 <br><br>
<li>
2017，APSys,<a href="https://dl.acm.org/doi/10.1145/3124680.3124717">The Case for Writing a Kernel in Rust</a>
<br><br>
报告了用rust编写资源高效的嵌入式内核的经验,并认为Rust通过使用线性类型系统来避免运行时内存管理的选择将使下一代安全操作系统成为可能。
<br>
Amit Levy, Bradford Campbell, Branden Ghena, Pat Pannuto, Prabal Dutta, Philip Levis:
The Case for Writing a Kernel in Rust.APSys 2017: 1:1-1:7
 </li>
 <br><br>
<li>
2020,<a href="https://ethz.ch/content/dam/ethz/special-interest/infk/chair-program-method/pm/documents/Education/Theses/Julian_Dunskus_BS_Report.pdf">Developing IDE Support for a Rust Verifier</a>
<br><br>
改进了Prusti，一个Rust语言的验证器。
 </li>
  <br><br>
<li>
2019,PLOS，<a href="https://dl.acm.org/doi/10.1145/3365137.3365395">Exploring Rust for Unikernel Development.</a>
<br><br>
提出了RustyHermit，用Rust重写了HermitCore ，
并将RustyHermit与基于C的内核HermitCore进行了比较，证明了Rusty实现的性能
与C实现相当。
 </li>
 <br><br>
<li>
2020,ISC，<a href="https://link.springer.com/chapter/10.1007/978-3-030-59851-8_22">RustyHermit: A Scalable, Rust-Based Virtual Execution Environment</a>
<br><br>
将基于Rust的IP堆栈集成到RustyHermit中。
 </li>
  <br><br>
<li>
2020,ISC，<a href="https://dspace.mit.edu/handle/1721.1/121669">Secure input validation in Rust with parsing-expression grammars</a>
<br><br>
提出了输入数据的自动验证（AVID），来帮助解决内核中的输入验证问题。
 </li>
  <br><br>
<li>
2018，<a href="https://ethz.ch/content/dam/ethz/special-interest/infk/chair-program-method/pm/documents/Education/Theses/Dominik_Dietler_BA_report.pdf">Visualization of Lifetime Constraints in Rust</a>
<br><br>
提供了一个算法来识别一组提供生命周期错误信息的源代码行，并对这些错误进行推理。并在一个原型中实现了这些，该原型生成了一个约束图，并显示了已识别的源代码行。
 </li>
  <br><br>
<li>
2017，<a href="https://ethz.ch/content/dam/ethz/special-interest/infk/chair-program-method/pm/documents/Education/Theses/David_Blaser_BA_Report.pdf">Simple Explanation of Complex Lifetime Errors in Rust</a>
<br><br>
提供了一个帮助程序员理解生命周期错误及其原因的工具，该工具为为程序中的生命周期错误创建可视化或基于文本的解释。
 </li>
  <br><br>
<li>
2019，CCS,<a href="https://dl.acm.org/doi/abs/10.1145/3133956.3138824">Poster: Rust SGX SDK: Towards memory safety in Intel SGX enclave</a>
<br><br>
展示了Rust SGX软件开发工具包，它将英特尔SGX和Rust编程语言结合在一起。通过使用Rust  SGX软件开发工具包，开发人员可以轻松地编写内存安全的飞地。（SGX是英特尔在其微处理器中引入的一个隔离机制，用来保护代码和数据免遭修改或泄漏。其建立的特殊隔离区域称为“飞地（enclaves）”，可以用于常规计算机和云服务器来储存与隔离每个程序的机密信英特尔SGX是下一代可信计算基础设施。它可以有效地保护飞地内的数据不被窃取。与传统项目类似，SGX飞地可能存在安全漏洞，也可能被利用。息，如加密密钥或密码等）
 </li>
  <br><br>
<li>
2020,<a href="https://34.201.211.163/handle/1721.1/128627">Preventing IPC-facilitated type confusion in Rust</a>
<br><br>
提出了safeIPC，一个Rust编译器扩展，它检测进程间通信，并插入运行时检查，以确保类型安全得到维护。如果通过IPC接收到的任何数据类型与期望的类型不相同，使用safeIPC检测的程序就会抛出运行时错误。
 </li>
  <br><br>
<li>
2020,<a href="https://www.diva-portal.org/smash/record.jsf?pid=diva2:1391552">Real time Rust on multi-core microcontrollers</a>
<br><br>
提出了一个可替代时间分片线程的编程框架，用于构建实时、安全和通用的嵌入式软件，经实验该框架适用于单核、
同构多核和异构多核系统。
 </li>
   <br><br>
<li>
2017,<a href="https://ieeexplore.ieee.org/abstract/document/8319363/">On utilizing rust programming language for Internet of Things</a>
<br><br>
总结了一些在嵌入式系统开发方面应用Rust的经验，以阐明将rust应用于物联网的合理性。
 </li>
   <br><br>
<li>
2017,<a href="https://sjmulder.nl/dl/pdf/unsorted/2018 - Ellmann - Writing Network Drivers in Rust.pdf">Writing network drivers in rust</a>
<br><br>
展示了一个用Rust编写的用户空间网络驱动程序，它是为简单、安全和性能而设计的，该驱动程序总共有1306行代码，不到10%的不安全代码，虽然比C语言中的参考实现性能稍差，但它足够快，可以在现实应用中使用，因为它比默认内核网络堆栈快六倍多。Rust除了性能之外最大的优点就是内存安全。
 </li>
   <br><br>
<li>
2015,<a href="http://cs.brown.edu/research/pubs/theses/ugrad/2015/light.alex.pdf">Reenix: Implementing a unix-like operating system
in rust</a>
<br><br>
提 出 了 Reenix， 旨 在 用 Rust 重 新 实 现Wineix操作系统。 虽然该项目没有完全实现，但是
创建了一个基本内核，支持协作调度多个内核进程、基本的设备驱动程序和基础虚拟文件系统，证明了使用rust构建类似unix的操作系统 内核是可行的。
 </li>
    <br><br>
<li>
2013,<a href="https://ieeexplore.ieee.org/document/6650903">GPU Programming in Rust:Implementing High-level Abstractions in a Systems-level Language</a>
<br><br>
演示了使用LLVM PTX直接从Rust生成GPU内核是可能的。
 </li>
        <br><br>
<li>
2017,<a href="https://dl.acm.org/doi/10.1145/3139645.3139660">System Programming in Rust: Beyond Safety</a>
<br><br>
表明Rust的线性类型系统能够实现传统语言无法有效实现的功能，比任何传统语言更能有效地实现强大的安全和可靠性机制，并用了三个例子展示了Rust的这种功能：零拷贝软件故障隔离、有效静态信息流分析和自动检查点。
<br>
Abhiram Balasubramanian, Marek S. Baranowski, Anton Burtsev, Aurojit Panda, Zvonimir Rakamaric, Leonid Ryzhyk:
System Programming in Rust: Beyond Safety. ACM SIGOPS Oper. Syst. Rev. 51(1): 94-99 (2017) </li>
        <br><br>
<li>
2015,WGP,<a href="https://dl.acm.org/doi/abs/10.1145/2808098.2808100">Session types for Rust</a>
<br><br>
在提供仿射类型的编程语言Rust中实现会话类型，并为其安全性进行了论证。
<br>
Thomas Bracht Laumann Jespersen, Philip Munksgaard, Ken Friis Larsen:
Session types for Rust. WGP@ICFP 2015: 13-22</li>
<br><br>
<li>
2020,CORR，<a href="[](https://arxiv.org/abs/2009.13619)">Ferrite: A judgmental embedding of session types in Rust</a>
<br><br>
本文介绍了Ferrite，这是Rust会话类型的浅层嵌入。与现有的用于mainstram语言的会话类型库和嵌入相反，Ferrite不仅支持线性会话类型，而且还支持共享会话类型。
<br>
Ruofei Chen, Stephanie Balzer:
Ferrite: A Judgmental Embedding of Session Types in Rust. CoRR abs/2009.13619 (2020)
 </li>
</ol>





##  Unsafe

1. 2020,ICSE,[Is rust used safely by software developers?](https://dl.acm.org/doi/10.1145/3377811.3380413)

   对Rust库和Rust应用程序进行了大规模的研究和分析，发现大多数的Rust crates 都不能完全保证内存安全和无数据竞争。

   方法：识别所有unsafe事件，然后确定unsafe是如何传播的。首先识别每个crate 中block，function，trait以及trait implementations 中unsafe 关键字的使用。然后开发两个版本的扩展调用图：乐观版与保守版（多态函数在运行时调用的是unsafe函数还是safe）。接着设计了一个算法来分析扩展调用图以确定一个函数是safe 还是possibly unsafe。通过这种方式可以识别看似安全，实则有潜在不安全条件的库。

   最后研究表明：大多数的unsafe rust的使用并不是直接使用unsafe关键字，而是通过函数之间的依赖关系。并且发现下载最多的crates 比其他crates有更多的unsafe 代码。从这些结果来看，用户很难知道他们的代码是否安全，作者提出了一些建议来帮助用户理解Unsafe Rust的使用。

2. 2020, CoRR，[Memory-Safety Challenge Considered Solved? An Empirical Study with All Rust CVEs.](https://arxiv.org/abs/2003.03296)

   本文调查了186个bug报告，其中包含了到2020-12-31为止的关于内存安全的所有Rust CVE （常见漏洞与纰漏）。

   研究表明Rust 所有内存安全bug（除了编译器bug）的触发都需要unsafe code，即在没有使用 unsafe code的情况下是不会触发内存安全问题的。并将造成内存安全bug的原因分为3类：

   自动回收内存引发的：自动回收内存bug与Rust采用的所有权的资源管理(OBRM)副作用相关。 Rust编译器强制自动销毁未使用的值，这样就可能导致许多use after free ，double free等问题。

   引入了不可靠的函数：包括使用了不可靠的API和FFI。

   与泛型 或者trait相关（trait 类似于其他语言中的interface，虽然有些不同）： Rust高级特性（泛型和trait）会加剧引入内存安全bug的风险。

3. 2020，PLDI，[Understanding memory and thread safety practices and issues in real-world Rust programs](https://dl.acm.org/doi/10.1145/3385412.3386036)

   - 如何使用、更改和封装不安全代码

     对不安全操作的封装应该要设置并检测前置条件和后置条件。但是并不是所有的条件都可以方便地检测，所以更加先进的bug检测与验证技术是刚需。

     将unsafe code改为safe code：对外部非Rust库的不安全调用改为用Rust编写，不安全的读写共享变量用原子指令取代，不安全的std函数可以用某些Rust编写的安全的std函数替代。

   - Rust程序存在的内存安全问题

     发现所有的内存安全bug都涉及到了unsafe code，甚至大多数竟涉及到了safe code。许多内存安全bug都是因为误用所有权以及生命周期引起的。

     内存安全bug大概分为两种：错误内存访问（如缓冲区溢出）和违反生命周期（如 use-after-free）。

   - Rust程序存在的并发安全问题

     并发bug包括非阻塞bug和阻塞bug两种。非阻塞bug可以发生在unsafe code中，也可能发生在safe code中，但是阻塞bug都发生在safe code 中（都是在safe code中使用内部不安全函数引起的）。尽管Rust中的许多bug都是传统并发bug（双锁，违反原子性等），但是造成这些bug的极大多数原因都是由于程序员误解了Rust的生命周期和安全规则造成的。

   - 设计了两个静态bug检测器（一个用于检测 use-after-free bug，一个用于检测双锁bug），并在先前研究过的Rust应用程序中发现了10个新bug。





##  内存安全



<ol>
<li>
 2018, CODASPY ，<a href="https://dl.acm.org/doi/10.1145/3176258.3176330">Fidelius Charm: Isolating Unsafe Rust Code</a>
  <br><br>
提出了Fidelius Charm(FC), 将地址空间划分为两个区域：可信任特权区域（可由函数控制，对于unsafe code来说不可见，即按需划分安全分隔区）和其他区域。这样就可以保护敏感数据（程序员指定）免受unsafe code带来的攻击及影响。
</li>
<br><br>
<li>
    2020，ICSE，<a href="https://dl.acm.org/doi/10.1145/3377811.3380325">Securing unsafe rust programs with XRust</a>
    <br><br>
    提出了XRust，设计并实现了一个新的堆分配器，将堆内存分为两个互斥的区域（将safe Rust 和unsafe Rust 的内存对象分开存储）并自动插入运行时检查，防止跨区域引用，确保safe Rust数据不会被unsafe Rust中产生内存错误所影响。
</li>
<br><br>
<li>2017,SOSP,<a href="https://dl.acm.org/doi/10.1145/3144555.3144562">Sandcrust: Automatic sandboxing of unsafe components in rust.</a>
<br><br>
	提出了Sandcrust（一个简单易用的沙盒解决方案），把C语言实现的库的代码和数据隔离在
	一个单独的进程里，这样Rust主程序会免受不安全C库中的bug导致的内存破坏。
    <br>
    Sandcrust基于Rust的宏系统, 只需要对调用库的API函数进行简单的注释，它在编译时会将包装C库API的注释函数翻译成对运行在沙盒进程中库实例的远程调用。
    </li>
<br><br>
    <li>
        2018,IEICE,<a href="https://www.jstage.jst.go.jp/article/transinf/E101.D/8/E101.D_2018EDL8040/_article">Detecting Unsafe Raw Pointer Dereferencing Behavior in Rust</a>
	<br><br>
	本文研究了原始指针解引用是如何在Rust中引起安全问题的（演示并分析了它如何导致生成多个可变引用、修改不可变值和访问自由值）。针对这些问题，提出了一种实用的、可移植的方法，该方法使用模式匹配来识别可用于生成非法多重可变引用的函数，并在运行时执行动态检查，该方法已经在Rust编译器插件上实现。
</li>
 <br><br>
    <li>
        2021,<a href="https://arxiv.org/abs/2103.15420">SafeDrop: Detecting Memory Deallocation Bugs of Rust Programs via Static Data-Flow Analysis</a>
	<br><br>
	研究了Rust中的错误的内存释放问题，并提出了一种静态的路径敏感数据流分析方法——SafeDrop，用于检测Rust中的内存释放冲突。并将其应用于Rust编译器，对Rust CVEs和Rust crates进行了彻底的评估，验证了SafeDrop的有效性。提出SafeDrop的方法可以用于一系列的安全检测，包括use after free、double free、悬空指针和由其他RAII系统中的自动内存释放引起的无效内存访问。
</li>
</ol>








##  线程安全



1. 2019,CoRR,[Fearless Concurrency? Understanding Concurrent Programming Safety in Real-World Rust Software](https://arxiv.org/abs/1902.01906)

   本文从两个方面对Rust的并发性进行研究：并发的使用以及Rust中存在的并发bug。

   并发bug分为两种：死锁bug和非死锁bug，其中数据争用bug是一种非常常见的非死锁bug。

   本文针对死锁bug和数据竞争bug进行研究，发现：

   ​	大部分死锁bug都是由双锁导致，其他的则是由误用信道引起。

   ​	对于数据争用bug，在unsafe code中存在，这是由不安全代码中的指令引起的。safe code中也存在数据争用bug，这些bug全都是误用原子操作引起的（因为Rust支持原子类型的共享变量，而且对原子变量进行读写操作会逃过Rust的所有权检查）。

   对未来的启示：传统的并发bug检测和修复技术要把重点放在互斥锁上，解决Rust中的并发bug应该多多关注channel和atomic。由于双锁和信道误用是造成死锁bug的主要原因，所以对于死锁bug的检测，我们可以设计一个静态分析系统，识别函数调用中可能的锁操作，以及根据线程之间的消息传递来推断出线程等待关系。而对于数据争用bug的检测，我们可以重点关注unsafe code以及safe code中的原子操作。

   Zeming Yu, Linhai Song, Yiying Zhang:
   Fearless Concurrency? Understanding Concurrent Programming Safety in Real-World Rust Software. CoRR abs/1902.01906 (2019)

   

2. 2019，CORR，[A Practical Analysis of Rust's Concurrency Story](https://arxiv.org/abs/1904.12210)

   开发者们常常通过使用锁来避免数据争用，然而因为锁序列化访问，所以一次只有一个线程可以访问数据，即使这些进程访问的是数据结构的不同部分，这样就会减慢程序运行速度。本文实现了无锁的并发hashmap,成为了Rust语言中最快的并发hashmap之一。并说明了在开发这个无锁并发hashmap时，Rust语言安全特性所产生的帮助和阻碍。

   Aditya Saligrama, Andrew Shen, Jon Gjengset:
   A Practical Analysis of Rust's Concurrency Story. CoRR abs/1904.12210 (2019)

   

3. 2020，Wuhan University Journal of Natural Sciences，[RSMC： A Safety Model Checker for Concurrency and Memory Safety of Rust](http://www.cnki.com.cn/Article/CJFDTotal-WHDZ202002006.htm)

   介绍了RSMC，一个基于SMACK的工具，用于检测Rust程序中的并发错误和内存安全错误。RSMC结合了并发原语模型检查和内存边界	模型检查，它可以通过断言生成器自动将安全属性断言插入到每个Rust程序中，以有效地检测并发安全bug和内存安全bug。实验结果	表明，该工具能够有效地检测Rust程序中的内存与并发bug。但是本文只关注了内存访问并发问题，并未考虑网络并发和文件并发。

   

4. 2018，[Transactional Memory in Rust](https://dash.harvard.edu/bitstream/handle/1/38811564/LIVELY-SENIORTHESIS-2018.pdf?sequence=3&isAllowed=y)

   描述了sto-rs（将sto移植到rust）的实现，并表明了Rust的类型系统可以用来提高STO的事务安全性。



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

























