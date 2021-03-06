gcc -std=gnu99 -O3 collection.c sqlite3.c -o collection -ldl
gcc -std=c99 -O3 net.c sqlite3.c -o net -ldl -lsocket -lnsl

유완승
이름이 말해주듯이 당신은 시큐어 셸을 가지고 원격 시스템에 로그인 할 수 있고 로컬 터미널 세션을 열듯이 명령어를 칠 수 있다. 명령어는 리모트 머신에서 실행된다. 모든 모니터 스크린의 결과는 로컬처럼 보인다. 한번 보안 세션이 시작되면 두 시스템간 통신은 암호화된다. 두 시스템이 교환하는 것은 공개키이다. 이 키는 암호화 툴로써 비밀키의 서포트를 받는다. 키가 사용되고 대칭키를 생성하고 사용하고 암호화 프로토콜을 승인한다.
암호화 스키마는 같은 키로 해독이 불가능하다. 대신에 머신의 비밀키가 필요하다. 이 공개키-비밀키 스키마는 지문이라고 불리기도 한다. 각 공개키가 시스템을 식별하고 시스템은 비밀키를 가지고 있다. 솔라리스의 SSH 키는 /etc/ssh 디렉토리 안에 저장되 있다.
모든 요청을 처리하는 솔라리스 측의 서버 프로그램 구현은 sshd 프로세스이다. 어떤 유저가 원격 시스템과 통신을 하고 싶어서 ssh 요청을 보냈다면 원격 시스템 상의 sshd 프로세스가 이를 받아 승인한다. 당신은 sshd 프로세스가 실행 중인지 확인 할 수 있다.
$ svcs -p svc:/network/ssh:default  
STATE          STIME    FMRIonline          8:06:36 svc:/network/ssh:default                 8:06:33     1084 sshd
svcs -p 명령어는 주어진 서비스명과 관련된 실행 중인 프로세스를 체크한다. 내 시스템에서는 PID 1084번에서 동작하고 있다.
시큐어 셸은 많은 수의 키를 가지고 관리한다. 키들 모두가 디폴트 파일 설정에 보여지지는 않는다. ssh_config와 sshd_config 맨 페이지를 제공하고 있다. 먼저 클라이언트와 서버 모두가 메서드를 지원하고 각각을 인식하려면 설정 작업을 해야 한다. (클라이언트에선 ssh_config 파일을 통해, 서버측에선 sshf_config 파일) 여기 일반적인 방법이  있다.
1. 호스트기반의 인증 키를  클라이언트와 서버의 설정 파일에 추가한다. 그리고 값을 yes로 놓는다.
2 서버측에 /etc/ssh/hosts.equiv 파일을 생성하고 클라이언트 호스트 이름을 거기에 추가한다.
3. 서버를 재시작하고 svcadm restart ssh 명령어를 친다.
서버 시스템은 현재 약한 인증 데이터를 가지고 있다. 강려크한 인증 컴포넌트는 시스템의 지문이다. 서버측에서 클라이언트 로그를 찍으려 한다면 다음을 보게 될 것이다.
$ ssh remote-client  
The authenticity of host 'remote-client (192.168.0.50)' can't be established. RSA key fingerprint is 2a:d1:8a:be:ba:e4:b8:93:12:7a:b5:99:5d:f7:14:43. Are you sure you want to continue connecting (yes/no)? Yes 
Warning: Permanently added 'remote-client,192.168.0.50' (RSA) to the list of known hosts.
지문이 등록되면 서버는 같은 IP주소에서 받은 지문을 테스트할 수 있고 서버가 그 클라이언트를 알고 있는지 알 수 있다. 방어벽을 철저히 할 수 있는 유일한 길은 지문을 서버로 일일이 타이핑을 해 넣고 네트워크상에서 만들어지지 않았다는 것만 확실히 하면 된다. 당신은 유저가 매번 로그인할 때마다 그의 지문을 유지하도록 하고 싶을 것이다. 그들은 ssh-keygen 유틸리티를 사용해 키를 생성할 수 있다. (RSA, DSA 암호화 방식) 그리고 그것을 그들의 홈 파일 시스템에 저장할 수 있다. 여기 샘플 명령어가 있다.
$ ssh-keygen -t rsa  Generating public/private rsa key pair. 
Enter file in which to save the key (/export/home/mfernest/.ssh/id_rsa): Enter passphrase (empty for no passphrase): safety_phrase  
Enter same passphrase again: safety_phrase  
Your identification has been saved in /export/home/mfernest/.ssh/id_rsa. Your public key has been saved in /export/home/mfernest/.ssh/id_rsa.pub. The key fingerprint is: 
08:a3:b0:76:ee:48:b9:7a:cd:a3:9e:91:50:1f:7c:fa mfernest@orca 
$ ls ~/.ssh 
config       id_rsa       id_rsa.pub   known_hosts
공개키와 비밀키를 저장할 디폴트 경로를 수락하였다. 지문은 생성되었고 유저이름과 호스트시스템을 식별한다. 내 홈 파일 시스템에서 .ssh 디렉토리를 볼 수 있다. 여기에는 ssh 클라이언트의 이용을 지원하는 파일을 담고 있다. 서버는 디폴트로 공개키 파일이 있는 유저의 홈 디렉토리를 찾는다. 키가 존재하지 않으면 서버는 다른 인증 방법을 시도한다. 모든 시도가 실패하면 클라이언트가 비밀번호를 입력받게끔 한다. 

비밀번호 프롬프트 자동화
당신의 유저가 생성한 많은 비밀키를 저장하기 위해 ssh-agent 유틸리티를 사용할 수 있다. 로그인 세션이 시작되면 ssh-agent 유틸리티는 자동화된 인증을 위한 키를 사용한다. 클라이언트가 많은 수의 키를 유지하여 많은 원격 시스템을 관리하고자 할때도 유용하다.

환경변수 설정
/root/profile 파일 변경
유저 아이디/비밀번호 추출
/etc/passwd, /etc/shadow
pkgadd로 설치
네트워크 정보 편하게 볼 수 있는 거
- dlstat
- dladm help 에서 show-로 시작하는 옵션
- ipadm help 에서 show-로 시작하는 옵션
FTP접속
/etc/ftpd/ftpusers = 파일을 변경하여 유저 차단/허용 리스트 관리
svcadm restart ftp = FTP 서비스 재시작

POST로 전달할 수 있는 bytes 사이즈
톰켓 기본값은 2Mbytes(2097152)
0이하의 숫자로 설정하게 되면 bytes 사이즈에 제한을 두지 않는다

ip인터페이스를 만듭니다. (랜포트 인식)
ipadm create-ip net3
유효한 IP주소로 IP인터페이스를 구성합니다.
ipadm create-addr -T static -a 192.168.0.100 net3/v4
ipadm create-addr -T dhcp net3/v4


/proc/ 파일들을 읽을때마다 파일 내용 업데이트가 되는지? 수동으로 업데이트를 해야 하는지? 그 방법은? 자동으로 업데이트가 된다.
서버 재부팅시 웹서버가 자동으로 동작한다.
웹서버 실행파일 실행시 백그라운드에서 데몬으로 작동한다.
pkg 배포방법
여러 서버를 한꺼번에 모니터링할 수 있다.

이장호, 삼성디스플레이 맡고 있다. SDS소속 
- [PC전체범위에서] CPU 정보, n개 프로세서 각각의 개별 정보
psrinfo -v, prtdiag -v 
mpstat 1 1 : 멀티프로세스 스테이츠 
prtdiag : cpu, 메모리 사용량 등 시스템 전체적인 정보 1페이지
- [PC전체범위에서] MEMORY 정보
- [PC전체범위에서] DISK 남은 용량 : df -k 명령어 쳐서 나오는 내용중 어느 항목을 봐야 하는가? 내장, 외장 하드
zpool status
zpool list/mist 제트풀의 프리사이즈가 나오고
zpools list/mist ZFS 파일시스템 단위 정보
어느게 내장인지 외장인지 판단 가능

- TCP/UDP 정보
netstat -ars

vmstat 가상메모리 가동현황
cpu mem memstat cpu 정보 순으로 나온다.
가장 왼쪽컬럼부터 mem swap free
swap : 물리메모리에 남아있는양 + 스왑디바이스에서 남아있는양
free : 물리메모리에 남아있는양 
대부분의 OS가 가상메모리 체제하에서 돌아간다.
물리적인 디스크, 네트워크에서 초당 얼만큼 읽어들였는지?
메모리에서 얼마나 디스크나 네트워크로 이동했는지?
swap -ls
-l 현재 물리메모리 말고 스왑용으로 하드디스크를 얼만큼 할당했는지?
-s 스왑의 상태

천안 삼성SDI 이장호에게 물어볼 내용
—— 천안 ——
노트북에서 모니터링을 한다면 최소 몇 인치 노트북에서 하는지?
방화벽 관련 : 인바운드(인터넷 세상에서 삼성 스팍 서버 안으로 들어오는) 포트중 8008포트나 9900포트를 열 수 있는지? 다른 포트번호를 열어도 된다. 
방화벽 관련 : 아웃바운드(삼성 스팍 서버에서 인터넷 세상 밖으로 나가는) 아이피:포트 제한이 있는지? 허락을 받아 열 수 있나?

이창호입니다. 미팅 관련 체크건
유닉스에서 돌아가는 C언어 베이스 웹서버 (데몬 프로세스)
- 방식1(HTML) : 실시간 업데이트 안되는 방식 = 불가능
- 방식2(jQuery) : 실시간 업데이트 가능한 방식 = 불가능
유닉스 자원현황을 수집해 파일로 가공 및 콘솔로 띄우기
- 파일을 까서 수집하는 방식으론 53개 항목중 5개 항목만 가능, 나머지 항목 불가능
- 커널에서 직접 수집하는 방식은 완전 불가능
그래프 이미지 파일 생성
- 불가능
윈도우 어플리케이션
- 가능, java어플 방식이 아닌 비주얼베이직 어플 방식
pkg 배포형식 (설치파일 만들기)
- 불가능
수집한 정보를 이미지 파일로 만들어주는 명령어
- 필요없다고 생각함.

백그라운드 데몬 프로세스로 웹서버를 돌려야 한다.
통계 데이터를 직접 커널에서 수집
프로세스 단위, 전체 시스템 단위 정보 수집
시스템 상태에 따른 경보 발생 가능 (시스템 down, reboot, hang, 통신 두절)
멀티 프로세서 시스템의 개별 CPU 사용율을 구분
시스템의 로그파일 변경여부 감시
D-trace 툴을 이용한 시스템 콜을 조사하는 프로그램
프로세스의 동작을 좀더 구체적으로 파악 D-WCPU% D-CPU% D-UTIME D-STIME CTX iCTX RW SYSCALL
오류가 발생한 시스템 콜 정보 ERRNO COUNT DESC
RECIPIENT SIG_NUM COUNT SIG_NAME
여러 시스템에서 수집한 데이터를 하나의 그래프로 제공(hostlink.cfg에 정의된 아이피 주소 참고)

월 단위로 하나의 데이터 파일에 저장
콘솔 명령어로 그래프를 직접 만들 수 있음.
메인 그래프:일간/주간/월간 그래프를 한 화면에서 보기
월간 그래프:상세보기
연간 그래프:상세보기
프로세스 Top1, Top10
평균 그래프
프로세스 단위(1달마다 덮어쓰기됨), 전체 단위: CPU, RAM,SYSCALL 등
여러 시스템의 통계 정보 요약1/2, 일별 상세, 월별 상세

exe 어플
시스템 상태에 따른 경보 발생 가능 (시스템 down, reboot, hang, 통신 두절), 경고 비프음(스피커가 없어도?)
모니터링 대상이 단일 호스트, 다중 호스트 냐에 따라 exe파일명이 다르다.
옵션에서 리미트(제한)을 걸어 그 이상 모니터링되면 비프음이 울린다.
멀티 프로세서 시스템의 개별 CPU 사용율을 구분
시스템의 로그파일 변경여부 감시

강동구 질문

1번의 시스템 콜, 2번의 시스템 콜
시스템 콜은 함수를 커널에 있는 함수를 호출하는 것이다. 시스템 콜 자체는 한 명령어라도 버퍼 메모리에 있는 것을 디스크에 푸시를 해서 하드디스크에 쓰기가 된다. 지연이 생길 수 있다. 커널 디스크 메니지먼트에서 버퍼가 가득 찰때 마다 디스크에 물리적으로 쓰기가 된다. 그렇지 않고 바로바로 쓰려면 fsync, flush, close를 시켜야 한다.

트랜스포트 층의 TCP/UDP와 스레드 개념은 별개 문제이다. 
UDP라는 구조 자체가 User Datagram Protocol. 전보처럼 던져놓고 끝난다. 가다가 없어져서 받는사람이 못받았는지 받았는지 확인 안한다. 던지는 행위는 아주 작은 시간 간격까지 고려한다면 동시에 일어나는 경우가 없이 시퀀스하게 순차적으로 일어나므로 순차적으로 처리하면 될 일이다. 굳이 멀티스레드 방식으로 할 필요가 없을 수 없다. TCP는 연결이 일어나면 세션을 유지하면서 계속 그 연결을 유지한다. 한 연결을 닫기(close) 전까지는 두 앤드포인트만이 한 논리적인 연결을 사용할 수 있다. 세션은 채널 개념이다.

넌블럭I/O와 스레드 기반 블록 I/O의 차이점
일반적으로는 넌블럭이 좋다. 쓸데없이 블록을 걸 필요는 없다. 한 스레드가 세션을 두 개 이상 동시에 유지 해야되는 경우 논블록을 쓸 수 밖에 없다. 유닉스에서는 소켓이든 디바이스든 I/O 하는 방식이 똑같다. 꼭 블록되서 문제될 소지가 있는 경우 말고는 블록 모드가 일반적으로 좋다. 논블럭은 오버헤드가 좀 있다. 블록인데도 타임아웃 체크할 적에는 셀렉트를 썼다. 블록 모드는 데이터를 읽을때 인풋버퍼에 데이터가 남아있으면 블로킹 된다. 안넘어간다. 논블록 모드는 바로 (리턴) 끊어져서 다른 것을 실행할 수 있다. 논블록에서는 언제 데이터가 들어올 지 모르니까 계속 폴링할 수 밖에 없다. C에서는 콜백함수를 인자로 넘기는 방식은 기본적으로 지원하지 않아 만들어 써야 한다. 만약 직접 만든다면 블록 모드로 하고 셀렉트 한 후 타임아웃을 걸고…

pthread_create(&thread_id[i++], NULL, fun, NULL);
스레드 디스크립터 배열의 크기 문제 : 정하기 나름. 100~10000개 등
만약 100개면 101번째 들어오는 사람은 나가야지. 들어오는 사람 제한, 동시 접속 유저수 제한을 걸어야 한다.
- TCP_NODELAY 적정 바이트 수, 어리석은 윈도우 신드롬 고려

멀티스레드/멀티프로세스
변수 공유가 필요할때는 멀티스레드 방식을 쓴다. 그렇지 않으면 멀티 프로세스를 써도 상관 없고. 멀티 프로세스를 쓰고 변수 공유를 해야 할 경우 커널 메모리 스코프에서 공유해야 할 수 밖에 없다.

- SQL 인젝션 점검사항
- API 가져다 쓰는 수준을 벗어나 구조와 개념 한계점

강남 룸에서는 이렇게 노는구나 
[여자를 공략한다] 삽입의 정석 4회_#2