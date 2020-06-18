

Антонио Моралез

В этом посте я поделюсь результатами первой части моего исследования фаззинга. В качестве практического примера я расскажу о своем фаззинг-анализе трех широко используемых FTP-серверов и подробно опишу уязвимости, найденные в результате этих усилий.

Выбор протокола FTP основан на следующих причинах:

* FTP является одним из наиболее широко используемых сетевых протоколов и имеет долгую историю;
* используются параллельные каналы связи (как командные, так и информационные);
* это интерактивный файловый сервер, позволяющий вносить изменения в файлы на стороне сервера;
* это простой текстовый протокол, который в принципе не оптимален для фаззинга (и мне нравятся проблемы!).
Я также приведу несколько советов о том, как справляться с любыми изменениями исходного кода, чтобы иметь возможность фаззить программное обеспечение, использующее сокеты, с использованием [AFL++](https://github.com/AFLplusplus/AFLplusplus).

# Выбранные серверы и результаты #
---------------------

Для начала я использовал API-интерфейс [SHODAN](https://www.shodan.io/) чтобы выбрать наиболее подходящие FTP-серверы из доступных вариантов FTP-серверов с открытым исходным кодом. Я выбрал FTP-серверы, которые имели наибольшее количество публично выставленных экземпляров:

* [Pure-FTPd](https://www.pureftpd.org/project/pure-ftpd/): самый популярный Linux ftpd
* [BFtpd](http://bftpd.sourceforge.net/): очень популярный ftpd для встраиваемых систем
* [ProFtpd](http://www.proftpd.org/): самый старый из трех, но все еще популярный Linux ftpd

В результате этих усилий я зарепортил следующие баги:

Software	CVE	Type
Pure-FTPd	CVE-2019-20176	Stack exhaustion in listdir (remote DoS)
Pure-FTPd	CVE-2020-9274	Uninitialized pointer in diraliases linked-list
Pure-FTPd	Not assigned	Broken SQL sanitizer in pw_pgsql_connect
Pure-FTPd	CVE-2020-9365	OOB read in pure_strcmp
Bftpd	CVE-2020-6162	OOB read in in hidegroups_init()
Bftpd	CVE-2020-6835	Multiple int-to-bool casting vulnerabilities, leading to heap overflow
ProFTPd	CVE-2020-9272	OOB read in mod_cap
ProFTPd	CVE-2020-9273	Use-after-free vulnerability in memory pools during data transfer
Fuzzing tips
When you want to fuzz software that uses sockets to obtain input, the first step to solving the problem generally involves making some source code changes to facilitate fuzzing. The fuzzing process is usually straightforward when the input is file based, as might be the case with image libraries such as libpng, libjpg, etc. In these cases, few or no changes to the targeted source code are required.

However, when dealing with networked, interactive servers (such as FTP servers), where the requests we send may cause all sorts of system state changes (uploads, downloads, parallel tasks, etc.), the process is not that simple.

A possible approach for such cases would be to make use of something like Preeny. Preeny is a set of preloaded libraries which help to simplify fuzzing and “pwning” tasks. Among other capabilities, Preeny allows you to de-socket software, i.e. redirecting socket data flow from/to stdin and stdout.

While it’s true that Preeny is a handy tool, its approach to de-socketing can remove the kind of granularity required to address the peculiarities of your fuzzing target. Every piece of software is unique, and we often want a high level of control over how and where to influence input and process state when fuzzing software to ensure we get the required amount of surface coverage. Because of this, I usually choose the manual source modification approach, which gives me greater flexibility in dealing with corner cases.

What follows are some practical tips to help you address common challenges when you start with socket based fuzzing, in the context of our FTP case study.

Sockets
Our FTP fuzzing will mainly focus on the command channel, which is the channel we use for transmitting FTP commands and receiving command responses.

In the Linux case it’s usually very simple to swap a network endpoint backed file descriptor for a file backed file descriptor without having to rewrite too much of the code.

![](https://securitylab.github.com/static/d7effe195eb9ece94e972345def04aa3/fddbb/fs-1.png)

In this case, inputFile is the current AFL file ([input_path]/.cur_input) which we pass as a custom argument.
![](https://securitylab.github.com/static/bec674cde43bb093734f5f7e22b27b8e/8f8c6/fs-2.png)

The AFL command line is as follows:

_afl-fuzz -t 1000 -m none -i './AFL/afl_in' -o './AFL/afl_out' -x ./AFL/dictionaries/basic.dict -- ./src/pure-ftpd -S 5000 -dd @@_

These changes mean that we cannot call certain network API functions such as getsockname and getnameinfo (we’d get an ENOTSOCK error). So I comment out these function calls and hard-code their associated result variables instead:

![](https://securitylab.github.com/static/2e476bfe9dad76eb74674620f8392665/fddbb/fs-3.png)

We also can’t use network fd specific operations such as send(3) so we have to move to a lower level non-network specific API such as write(2):
![](https://securitylab.github.com/static/a7c64bf2c4824da251f451cd8dd24693/fddbb/fs-4.png)
Up to this point we’ve only dealt with the command channel, but we also need to ensure that the data channel receives data so that uploads and downloads can function when we fuzz.

For the file upload case I use a call to getrandom(2) to return random file data:
![](https://securitylab.github.com/static/69525bba4ec192fcf09080ea51a25391/fddbb/fs-5.png)

For the file download case, we can directly write the file content to stderr:
![](https://securitylab.github.com/static/c6cec285e1db60ce5cfb9bfa936c852c/fddbb/fs-6.png)

Because we want to keep using stdin and stderr, we must avoid closing STDOUT_FILENO(1) and STDERR_FILENO(2) in the data channel code:
![](https://securitylab.github.com/static/98e5d7001a7d4b0be8ac55de86e7577e/672f7/fs-7.png)






