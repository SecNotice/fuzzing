
# Fuzzing сокетов, часть 1: Серверы FTP 


[Антонио Моралез](https://github.com/antonio-morales)

В этом посте я поделюсь результатами первой части моего исследования фаззинга. В качестве практического примера я расскажу о своем фаззинг-анализе трех широко используемых FTP-серверов и подробно опишу уязвимости, найденные в результате этих усилий.

Выбор протокола FTP основан на следующих причинах:

* FTP является одним из наиболее широко используемых сетевых протоколов и имеет долгую историю;
* используются параллельные каналы связи (как командные, так и информационные);
* это интерактивный файловый сервер, позволяющий вносить изменения в файлы на стороне сервера;
* это простой текстовый протокол, который в принципе не оптимален для фаззинга (и мне нравятся проблемы!).
Я также приведу несколько советов о том, как справляться с любыми изменениями исходного кода, чтобы иметь возможность фаззить программное обеспечение, использующее сокеты, с использованием [AFL++](https://github.com/AFLplusplus/AFLplusplus).

## Выбранные серверы и результаты ##
---------------------

Для начала я использовал API-интерфейс [SHODAN](https://www.shodan.io/) чтобы выбрать наиболее подходящие FTP-серверы из доступных вариантов FTP-серверов с открытым исходным кодом. Я выбрал FTP-серверы, которые имели наибольшее количество публично выставленных экземпляров:

*  **[Pure-FTPd](https://www.pureftpd.org/project/pure-ftpd/)**: самый популярный Linux ftpd
*  **[BFtpd](http://bftpd.sourceforge.net/)**: очень популярный ftpd для встраиваемых систем
*  **[ProFtpd](http://www.proftpd.org/)**: самый старый из трех, но все еще популярный Linux ftpd




As a result of this effort, I reported the following bugs:

<table>
<tbody>
<tr>
<td>Software</td>
<td>CVE</td>
<td>Type</td>
</tr>
<tr>
<td>Pure-FTPd</td>
<td>CVE-2019-20176</td>
<td>Stack exhaustion in listdir (remote DoS)</td>
</tr>

<tr>

<td>Pure-FTPd</td>

<td>CVE-2020-9274</td>

<td>Uninitialized pointer in diraliases linked-list</td>

</tr>

<tr>

<td>Pure-FTPd</td>

<td>Not assigned</td>

<td>Broken SQL sanitizer in pw_pgsql_connect</td>

</tr>

<tr>

<td>Pure-FTPd</td>

<td>CVE-2020-9365</td>

<td>OOB read in pure_strcmp</td>

</tr>

<tr>

<td>Bftpd</td>

<td>CVE-2020-6162</td>

<td>OOB read in in hidegroups_init()</td>

</tr>

<tr>

<td>Bftpd</td>

<td>CVE-2020-6835</td>

<td>Multiple int-to-bool casting vulnerabilities, leading to heap overflow</td>

</tr>

<tr>

<td>ProFTPd</td>

<td>CVE-2020-9272</td>

<td>OOB read in mod_cap</td>

</tr>

<tr>

<td>ProFTPd</td>

<td>CVE-2020-9273</td>

<td>Use-after-free vulnerability in memory pools during data transfer</td>

</tr>

</tbody>

</table>

## Советы по фаззингу

Если вы хотите использовать программное обеспечение, которое использует сокеты для получения входных данных, первый шаг к решению проблемы, как правило, включает внесение некоторых изменений в исходный код для облегчения фаззинга. Процесс фаззинга обычно прост, когда входные данные основаны на файлах, как это может быть в случае с библиотеками изображений, такими как libpng, libjpg и т.д. В этих случаях требуется небольшое изменение целевого исходного кода или даже не требуется и его.

However, when dealing with networked, interactive servers (such as FTP servers), where the requests we send may cause all sorts of system state changes (uploads, downloads, parallel tasks, etc.), the process is not that simple.
Однако при работе с сетевыми интерактивными серверами (такими как FTP-серверы), где отправляемые нами запросы могут вызывать всевозможные изменения состояния системы (загрузка, загрузка, параллельные задачи и т. Д.), Процесс не так прост.

A possible approach for such cases would be to make use of something like Preeny. [Preeny](https://github.com/zardus/preeny) is a set of preloaded libraries which help to simplify fuzzing and “pwning” tasks. Among other capabilities, Preeny allows you to **de-socket** software, i.e. redirecting socket data flow from/to stdin and stdout.
Возможный подход для таких случаев будет использовать что-то вроде Preeny. Preeny - это набор предустановленных библиотек, которые помогают упростить задачи фаззинга и pwning. Помимо других возможностей, Preeny позволяет отключать программное обеспечение от сокетов, то есть перенаправлять поток данных сокетов с / на stdin и stdout.

While it’s true that Preeny is a handy tool, its approach to de-socketing can remove the kind of granularity required to address the peculiarities of your fuzzing target. Every piece of software is unique, and we often want a high level of control over how and where to influence input and process state when fuzzing software to ensure we get the required amount of surface coverage. Because of this, I usually choose the manual source modification approach, which gives me greater flexibility in dealing with corner cases.
Несмотря на то, что Preeny - удобный инструмент, его подход к удалению сокетов может устранить степень детализации, необходимую для решения особенностей вашей размытой цели. Каждая часть программного обеспечения уникальна, и нам часто требуется высокий уровень контроля над тем, как и где влиять на состояние ввода и процесса при фаззинге программного обеспечения, чтобы гарантировать получение необходимого количества покрытия поверхности. Из-за этого я обычно выбираю подход к модификации исходного кода, который дает мне большую гибкость при работе с угловыми случаями.

What follows are some practical tips to help you address common challenges when you start with socket based fuzzing, in the context of our FTP case study.
Ниже приведены некоторые практические советы, которые помогут вам решить распространенные проблемы, когда вы начнете с фаззинга на основе сокетов, в контексте нашего примера внедрения FTP.

### Sockets

Our FTP fuzzing will mainly focus on the **command channel**, which is the channel we use for transmitting FTP commands and receiving command responses.
В нашем размышлении по FTP основное внимание будет уделено командному каналу, который мы используем для передачи команд FTP и получения ответов на команды.

In the Linux case it’s usually very simple to swap a network endpoint backed file descriptor for a file backed file descriptor without having to rewrite too much of the code.
В случае Linux обычно очень просто поменять дескриптор файла с файловой поддержкой конечной точки на дескриптор файла с файловой поддержкой без необходимости переписывать слишком большую часть кода.

[![Changes in ProFTPD code: turning a network file descriptor into a regular file descriptor](/static/d7effe195eb9ece94e972345def04aa3/fddbb/fs-1.png)](/static/d7effe195eb9ece94e972345def04aa3/47573/fs-1.png)
Изменения в коде ProFTPD: превращение сетевого дескриптора файла в обычный дескриптор файла

In this case, inputFile is the current AFL file ([input_path]/.cur_input) which we pass as a custom argument.
В этом случае inputFile - это текущий файл AFL ([input_path] /. Cur_input), который мы передаем в качестве пользовательского аргумента.

[![Extracting inputFile from command line](/static/bec674cde43bb093734f5f7e22b27b8e/8f8c6/fs-2.png)](/static/bec674cde43bb093734f5f7e22b27b8e/8f8c6/fs-2.png)
Извлечение inputFile из командной строки

The AFL command line is as follows:
Командная строка AFL выглядит следующим образом:

_afl-fuzz -t 1000 -m none -i './AFL/afl_in' -o './AFL/afl_out' -x ./AFL/dictionaries/basic.dict -- ./src/pure-ftpd -S 5000 -dd @@_

These changes mean that we cannot call certain network API functions such as getsockname and getnameinfo (we’d get an ENOTSOCK error). So I comment out these function calls and hard-code their associated result variables instead:
Эти изменения означают, что мы не можем вызывать определенные функции сетевого API, такие как getsockname и getnameinfo (мы получили ошибку ENOTSOCK). Поэтому я закомментирую эти вызовы функций и жестко закодирую связанные с ними переменные результата:

[![Changes in PureFTPd: Comment out getsockname and getnameinfo](/static/2e476bfe9dad76eb74674620f8392665/fddbb/fs-3.png)](/static/2e476bfe9dad76eb74674620f8392665/4f1c7/fs-3.png)

We also can’t use network fd specific operations such as send(3) so we have to move to a lower level non-network specific API such as write(2):

[![Changes in BFTPd: send call by write call](/static/a7c64bf2c4824da251f451cd8dd24693/fddbb/fs-4.png)](/static/a7c64bf2c4824da251f451cd8dd24693/7a513/fs-4.png)

Up to this point we’ve only dealt with the command channel, but we also need to ensure that the data channel receives data so that uploads and downloads can function when we fuzz.

For the **file upload case** I use a call to getrandom(2) to return random file data:

[![Changes in PureFTPd: call to linux getrandom(2) for retrieving random data](/static/69525bba4ec192fcf09080ea51a25391/fddbb/fs-5.png)](/static/69525bba4ec192fcf09080ea51a25391/9435c/fs-5.png)

For the **file download case,** we can directly write the file content to stderr:

[![Changes in PureFTPd: redirection of data channel output to stderr](/static/c6cec285e1db60ce5cfb9bfa936c852c/fddbb/fs-6.png)](/static/c6cec285e1db60ce5cfb9bfa936c852c/72501/fs-6.png)

Because we want to keep using stdin and stderr, we must avoid closing STDOUT_FILENO(1) and STDERR_FILENO(2) in the data channel code:

[![Changes in PureFTPd: Avoid to close STDOUT and STDERR file descriptors](/static/98e5d7001a7d4b0be8ac55de86e7577e/672f7/fs-7.png)](/static/98e5d7001a7d4b0be8ac55de86e7577e/672f7/fs-7.png)

We also need to modify the reading/write functions that depend on external libraries, as is the case with **OpenSSL**:

[![Changes in PureFTPd: writing ssl connection output to STDOUT](/static/e21e99b60270e333b2e3e3cf50729e7e/fddbb/fs-8.png)](/static/e21e99b60270e333b2e3e3cf50729e7e/6ca41/fs-8.png)

### Modifying file system calls

Because we want to maximize the chances of finding a vulnerability, it’s helpful to delete certain system calls such as unlink(2). This will prevent the fuzzer from deleting files by accident.

[![Changes in ProFTPD: Comment out unlink calls](/static/25e46a076f5499ee72501f60b1cc2de2/c5a17/fs-9.png)](/static/25e46a076f5499ee72501f60b1cc2de2/c5a17/fs-9.png)

Likewise, we delete any calls to rmdir(2) (directory deletion function in Linux):

[![Changes in BFTPd: Comment out rmdir calls](/static/aded8af3082b3a5007335cdb55575d6a/c5a17/fs-10.png)](/static/aded8af3082b3a5007335cdb55575d6a/c5a17/fs-10.png)

Since the fuzzer may end up modifying folder permissions, it’s important to periodically restore the original permissions. This way we avoid the fuzzer getting stuck:

[![Changes in ProFTPd: Restoring privileges in FTP default dir](/static/443c21bbdd57a2f8b740b1324eca7e06/66920/fs-11.png)](/static/443c21bbdd57a2f8b740b1324eca7e06/66920/fs-11.png)

### Event handling

Analyzing multiple event combinations will require the modification of event handling functions. For example, below I’ve replaced the call to poll by a call to FUZZ_poll:

[![Changes in PureFTPd: Call to poll function replaced by FUZZ_poll call](/static/5b98e8146a2a938be35571d54166756b/fddbb/fs-12.png)](/static/5b98e8146a2a938be35571d54166756b/6bcd1/fs-12.png)

This function is very simple, and just increments fds[0].revents and fds[1].revents values depending on RAND_MAX/10 and RAND_MAX/5 probability:

[![Custom poll function](/static/613a5b903045dc96e99fa90b9be607d5/2a182/fs-13.png)](/static/613a5b903045dc96e99fa90b9be607d5/2a182/fs-13.png)

You often want to delete or replace moot event polling code altogether since it doesn’t contribute to our surface coverage and just introduces unneeded complexity. In the following example, we patch out a moot select(2) call to that end.

[![Changes in ProFTPD: Comment out select call](/static/ceb0cb66da1ba98ff9c5c48cada23dca/fddbb/fs-14.png)](/static/ceb0cb66da1ba98ff9c5c48cada23dca/73d01/fs-14.png)

We must also take into account any situation where concurrent events between the data channel and the command channel get interleaved. CVE-2020-9273 is a good example of this occurring. This bug is triggered by sending a specific command sequence to the command channel while a data transfer is also running. To deal with that situation, I’ve built a small fuzzer function fuzzer_5tc2 that feeds strings from the provided dictionary to the fuzzer:

[![Changes in PureFTPd: custom fuzzing function that feeds strings from a dictionary](/static/0d9516eb604454c9cb4d944dd1830f56/fddbb/fs-15.png)](/static/0d9516eb604454c9cb4d944dd1830f56/92cc8/fs-15.png)

### Bye bye forks

Most Linux network server software uses a multi-process architecture. The parent server process listens for client connections and it forks a child process for each one of these connections. This mechanism also offers an opportunity for privilege separation between a privileged parent process and its child processes, as child processes can drop privileges without affecting the parent process.

However, AFL is unable to handle multi-process applications since it only detects signals generated by the parent process. For this reason, we need to transform our multi-process application into a single-process application. That implies we have to disable any fork(2) calls.

In some cases this functionality is already offered by the software itself. For example, here’s a look at the nofork option in ProFTPd:

The nofork option prevents proftpd from using the fork(2) system call turning proftpd into a single-process server

$ ./configure --enable-devel=coredump:nodaemon:nofork:profile:stacktrace ...

In the absence of any such options, to avoid fork(2), we just delete the actual fork(2) invocation and hardcode a return value of 0 which will continue down the intended child process execution path:

[![Changes in PureFTPd: fork commented](/static/0979e153faee1ce14ce0550d21906dba/e82b9/fs-16.png)](/static/0979e153faee1ce14ce0550d21906dba/e82b9/fs-16.png)

### chroot and permissions

The majority of FTP server attack surface is only available post authentication. For this reason, we must make sure that the fuzzer is authenticating successfully to the target FTP server. For this purpose, I added a fuzzing user to the system which is used to authenticate to the target FTP server process and I add this user authentication into my input corpus and my fuzzing dictionary.

Once the user is logged in, the FTP server usually calls chroot(2) to change the effective root directory for the process. This presents us with some obstacles as it may prevent our target process from accessing data we want it to be able to access.

For example, the child process path may drop privileges and we may no longer be able to access the AFL .cur_input file. To address this, the following is a simple example in which we just set the file world readable/writable/executable:

[![Changes in ProFTPd: Changing .cur_input permissions](/static/bb906c6ba120cafdc9dbe7467c5c2e38/60eaf/fs-17.png)](/static/bb906c6ba120cafdc9dbe7467c5c2e38/60eaf/fs-17.png)

### Reducing randomness

In order to improve the AFL stability score, we need to minimize randomness in our program. That way, the fuzzer will always cover the same execution code paths for the same inputs.

In the following example, we neuter the random number generation and return a repeatable RNG state:

[![Changes in PureFTPd: Setting a fixed rng](/static/fa8624a859a3ea57215a9b0805a0445d/fddbb/fs-18.png)](/static/fa8624a859a3ea57215a9b0805a0445d/b828e/fs-18.png)

[![Changes in ProFTPd: Initializing srandom with a fixed value](/static/c8c475d332752b45b4a228042bb4c947/51c61/fs-19.png)](/static/c8c475d332752b45b4a228042bb4c947/51c61/fs-19.png)

### Signals

Many applications include their own signal handlers to replace the default Linux signal handlers. This can cause errors in AFL by preventing it from catching specific signals. We generally don’t want to delete all signal handlers as this can cause unexpected behavior in the application, so we must identify any signals which could lead to errors in AFL execution.

[![Code snippet from ProFTPd: Signal handling](/static/9007ff5b0cdc66140ac7cddab885d8b7/337b6/fs-20.png)](/static/9007ff5b0cdc66140ac7cddab885d8b7/337b6/fs-20.png)

Comment out calls to alarm(2) function can also be helpful:

[![Changes in BFTPd: Comment out calls to alarm](/static/1cbce2437b5b1e2f1787352b008a17c8/fddbb/fs-21.png)](/static/1cbce2437b5b1e2f1787352b008a17c8/3658a/fs-21.png)

### Avoiding delays and optimizing

Timing is critical, even more so when we talk about fuzzing. Any unneeded delays must be minimized in the application to increase fuzzing speed. In the following example, we make timing intervals smaller where possible and remove unneeded calls to sleep(3) or usleep(3):

[![Changes in ProFTPD: Reducing delay time](/static/16740e422c06033e75f2bcc44c97cd89/fddbb/fs-22.png)](/static/16740e422c06033e75f2bcc44c97cd89/8ff1e/fs-22.png)

[![Changes in PureFTPd: comment out usleep](/static/8415b829bb2478414b78c028131f6613/c5a17/fs-23.png)](/static/8415b829bb2478414b78c028131f6613/c5a17/fs-23.png)

Likewise, often when fuzzing, you’ll notice that small changes in logic flow can speed up the fuzzing process tremendously. For example, as the number of generated files increases, the execution time of the listdir command grew, so I chose to only execute listdir once every N times:

[![Changes in PureFTPd: reduced executions of listdir to speed up fuzzing](/static/e9d581457b99c7ed90afc92bb1f7cca2/c5a17/fs-24.png)](/static/e9d581457b99c7ed90afc92bb1f7cca2/c5a17/fs-24.png)

### One last point

As a final point, I want to highlight an aspect that’s often overlooked: **FUZZING IS NOT A FULLY AUTOMATED PROCESS**.

Effective fuzzing requires **detailed knowledge of the internals of the software** we want to analyze, as well as an effective **strategy** for achieving good code coverage in all possible execution scenarios.

For example, to effectively fuzz the FTP servers we tackled in this case study, we had to modify nearly **1,500 lines of code**:

[![alt_text](/static/00c68433df4bacc8eda223de0982876a/67648/fs-25.png)](/static/00c68433df4bacc8eda223de0982876a/67648/fs-25.png)

The process of integrating the targeted code and the fuzzer, is a task that requires significant effort and is critical for obtaining successful results. It’s a highly sought-after goal in the fuzzing community as evidenced by the fact that rewards are quite high, such as [Google offering up to $20.000](https://www.google.com/about/appsecurity/patch-rewards/) for integrating security-critical projects with OSS-Fuzz.

This should inspire developers to facilitate fuzzing, as well as inspire the creation of fuzzing harnesses that ease the integration with AFL and LibFuzzer. As my colleague [Kevin](https://github.com/kevinbackhouse) recently wrote, [”the concept of anti-fuzzing is just ridiculous”](how-to-escape-from-the-fuzz). Please, **avoid security by obscurity**.

## Input corpus

As far as fuzzing input corpus is concerned for this project, my main goal was to achieve full edge coverage for all FTP commands, as well as a diverse combination of execution scenarios to obtain a reasonably complete path coverage.

[![Ideal initial scenario](/static/6a428fbb7fa0acca55ea79da9ae7752c/d51e0/fs-26.png)](/static/6a428fbb7fa0acca55ea79da9ae7752c/d51e0/fs-26.png)

Check out the **[input corpus](https://github.com/antonio-morales/Fuzzing/tree/master/Input%20Corpus/FTP/PureFTPd)** I’ve used for PureFTPd. And you can also find here [an example of a simple FTP fuzzing dictionary](https://github.com/antonio-morales/Fuzzing/blob/master/Dictionaries/FTP/Example.dict.txt).

## Vulnerability details

In this section, I’ll detail some of the more interesting vulnerabilities I found as a result of this fuzzing effort.

### CVE-2020-9273

This bug allows you to corrupt the ProFTPd memory pool by sending specific data to the command channel while a transfer is active in the data channel. The simplest example would be to send the interrupt character Ctrl+c. This results in a **Use-After-Free bug** in ProFTPd memory pools.

The ProFTPd memory pools implementation is based on Apache HTTP Server and is structured in a **hierarchical way** (longer to shorter lifetime).

[![Hierarchical structure of pools](/static/de356f4e71fecf45dfcec756a7723f89/fddbb/fs-27.png)](/static/de356f4e71fecf45dfcec756a7723f89/e3e30/fs-27.png)

Internally, each pool is structured as a linked-list of resources and these resources are freed automatically when the pool is destroyed.

[![Graphical representation of a memory pool (simplified)](/static/f63476b659abf3223ecc82a9188a9a05/fddbb/fs-28.png)](/static/f63476b659abf3223ecc82a9188a9a05/9199c/fs-28.png)

Each time pcalloc (ProFTPd’s dynamic allocator) is called, it tries to meet the demand using the available memory from the last element of the linked-list. If more memory than the available amount is required, pcalloc adds a new block at the end of the linked-list by calling the new_block function.

[![Call to new_block when available free space is not big enough](/static/dbff8b7028ec6752da0547caf336905a/6c314/fs-29.png)](/static/dbff8b7028ec6752da0547caf336905a/6c314/fs-29.png)

The problem is that the new_block function is not secure when used in concurrent scenarios, and under certain circumstances, the new_block function can grab a block that’s already present in the pool as a free block, causing pool list corruption.

[![Example of corrupted memory pool](/static/4c8730ac37fc93f50808c3c2e906a0c9/fddbb/fs-30.png)](/static/4c8730ac37fc93f50808c3c2e906a0c9/9199c/fs-30.png)

In the following example, we can see the pool is damaged since the outlined memory values are not valid memory addresses:

[![Corrupted addresses](/static/f094ec11bc54618a8a9e17f4ee05e887/fddbb/fs-31.png)](/static/f094ec11bc54618a8a9e17f4ee05e887/0324b/fs-31.png)

The severity of this bug is considerable given that:

*   It’s likely fully **exploitable**, since a write primitive can be obtained from the Use-After-Free
*   The memory pool corruption can lead to additional vulnerabilities such as **OOB-Write** or **OOB-Read**

### CVE-2020-9365

This bug is an **OOB-Read** vulnerability that affects the pure_strcmp function in **Pure-FTPd**. As shown in the next code snippet, the bug is due to the fact that **s1 and s2 strings can be different sizes**.

[![Vulnerable code](/static/6276214d998d04d1c07cb5b564204cf6/e9b2e/fs-32.jpg)](/static/6276214d998d04d1c07cb5b564204cf6/22a9e/fs-32.jpg)

Therefore, if the length of s1 is greater than s2 then the for loop will do len-1 iterations, where len-1 > strlen(s2). As a result, the program accesses memory that’s outside of the boundaries of the s2 array.

This issue may allow attackers to leak sensitive information from PureFTPd process memory or crash the PureFTPD process itself.

### CVE-2020-9274

In this case, we found an uninitialized pointer vulnerability that could also result in an Out-of-Bounds read.

The source of the problem comes from the init_aliases function in diraliases.c. In this function, the next member of the last item in the linked list is not set to NULL.

[![The next member of the last item is not set to NULL](/static/6f66e2d02f588ddaaba8b4a0f9c6d517/fddbb/fs-33.png)](/static/6f66e2d02f588ddaaba8b4a0f9c6d517/9f7a2/fs-33.png)

As a result, when the lookup_alias(const char *alias) or print_aliases(void) functions are called, they fail to correctly detect the end of the linked-list and try to access a non-existent list member.

[![The strcmp instruction can read memory from outside the linked-list](/static/d93b6ad64d4bc958888ee8e61ce54c86/569a0/fs-34.png)](/static/d93b6ad64d4bc958888ee8e61ce54c86/569a0/fs-34.png)

The severity of this vulnerability depends on the underlying operating system and whether or not it zeroes out the backing memory by default, since that affects the default values of the curr variable.

## Acknowledgments

I want to thank the developers of PureFTPd, BFTPd, and ProFTPD for their close collaboration on addressing these bugs. They fixed these issues in record time and it was a pleasure working with them!

Take a look at the tools and references I used throughout this post for further reading:

*   [PureFTPd](https://www.pureftpd.org/project/pure-ftpd/)
*   [Bftpd](http://bftpd.sourceforge.net/)
*   [ProFTPD](http://www.proftpd.org/)
*   [AFL++](https://github.com/AFLplusplus/AFLplusplus)







