export const bsiLabQuestions = [
  {
    'text': '1. Sieci VPN można zbudować wykorzystując:',
    'answers': [
      { 'text': 'IDS', 'correct': false },
      { 'text': 'Wireguard', 'correct': true },
      { 'text': 'TLS', 'correct': true },
      { 'text': 'SIEM', 'correct': false },
    ],
  },
  {
    'text':
      '2. Użytkownik Windows, będący administratorem, po zalogowaniu się do systemu:',
    'answers': [
      {
        'text':
          'otrzyma pełny token uprawnień i zawsze będzie korzystał z pełnego tokenu',
        'correct': false,
      },
      {
        'text':
          'otrzyma token pełny i ograniczony, zawsze będzie korzystał z pełnego tokenu',
        'correct': false,
      },
      {
        'text':
          'otrzyma token pełny i ograniczony, będzie mógł korzystać z jednego lub drugiego',
        'correct': true,
      },
      {
        'text':
          'otrzyma tylko token ograniczony, ale będzie mógł wykorzystać pełny token przy użyciu mechanizmu impersonation',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '6. Które komponenty systemu operacyjnego Windows mogą korzystać ze sprzętowej wirtualizacji celem podniesienia bezpieczeństwa systemu:',
    'answers': [
      { 'text': 'Alpine docker containers', 'correct': false },
      { 'text': 'Defender Application Guard', 'correct': true },
      { 'text': 'AppContainer', 'correct': false },
      { 'text': 'Ring - 1 compartmentalization', 'correct': false },
    ],
  },
  {
    'text': '10. Komputer-Twierdza:',
    'answers': [
      {
        'text': 'dopuszcza komunikację przechodzącą tylko przez usługi proxy',
        'correct': true,
      },
      {
        'text': 'to rodzaj zapory sieciowej z filtracją pakietów i modułem IDS',
        'correct': false,
      },
      {
        'text': 'jest implementacją zapory typu Application Layer Gateway',
        'correct': false,
      },
      {
        'text': 'pełni rolę zaufanej strony trzeciej w domenie Kerberos',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '19. Wskaż prawdziwe stwierdzenia dotyczące bramy aplikacyjnej Application Layer Gateway:',
    'answers': [
      {
        'text':
          'pośredniczy w komunikacji wyłącznie na poziomie warstwy aplikacyjnej',
        'correct': true,
      },
      {
        'text':
          'optymalizuje ruch stosując filtrację kontekstową na podstawie tablicy aktywnych połączeń',
        'correct': false,
      },
      {
        'text':
          'wymaga działającego poprawnie routingu między interfejsami sieciowymi',
        'correct': false,
      },
      {
        'text':
          'filtruje pakiety na poziomie wszystkich 3 warstw: sieciowej, transportowej i aplikacyjnej',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '21. Technologie umożliwiające ochronę integralności transmitowanych danych to m.in:',
    'answers': [
      { 'text': 'protokół TLS', 'correct': true },
      { 'text': 'protokół AH', 'correct': true },
      { 'text': 'protokół ESP', 'correct': true },
      { 'text': 'SYN cookies', 'correct': false },
    ],
  },
  {
    'text':
      '24. Wskaż mechanizmy systemu operacyjnego będące realizacją (choćby częściową) koncepcji piaskownicy:',
    'answers': [
      { 'text': 'Windows AppContainer', 'correct': true },
      { 'text': 'SSL/TLS', 'correct': false },
      { 'text': 'click-jacking', 'correct': false },
      { 'text': 'wirtualizacja systemu operacyjnego', 'correct': true },
    ],
  },
  {
    'text':
      '25. Pewna zapora sieciowa filtrująca pakiety realizuje jednocześnie funkcje NAT. Które opisy pasują do takiej zapory:',
    'answers': [
      {
        'text':
          'filtracja DNAT może być dokonywana dla pakietów przechodzących przez zaporę niezależnie od kierunku',
        'correct': false,
      },
      {
        'text':
          'translacja DNAT musi być dokonana przed routingiem pakietu aby pozycje tablicy routingu mogły być prawidłowo dopasowane',
        'correct': true,
      },
      {
        'text':
          'translacja DNAT musi być dokonana przed filtracją pakietu na interfejsie wejściowym, aby reguły łańcucha wejściowego mogły być prawidłowo dopasowane',
        'correct': false,
      },
      {
        'text':
          'translacja SNAT musi być dokonana przed filtracją kontekstową na interfejsie wyjściowym, aby pakiet znalazł prawidłowe dopasowanie do tablicy aktywnych połączeń',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '29. Które z poniższych mechanizmów pozwalają w systemie operacyjnym na chwilowe uzyskanie innych uprawnień dostępu niż posiadane aktualnie przez użytkownika:',
    'answers': [
      { 'text': 'Windows UAC', 'correct': true },
      { 'text': 'POSIX ACL', 'correct': false },
      { 'text': 'sudo', 'correct': true },
      { 'text': 'POSIX CAP', 'correct': true },
    ],
  },
  {
    'text': '30. Wskaż cechy mechanizmu AppContainer:',
    'answers': [
      {
        'text': 'kontroluje wywołania funkcji jądra systemu operacyjnego',
        'correct': false,
      },
      {
        'text':
          'jest "lekkim" odpowiednikiem maszyny wirtualnej, z tą różnicą, że nie zawiera zwirtualizowanego systemu operacyjnego, tylko aplikację i potrzebne biblioteki',
        'correct': false,
      },
      {
        'text':
          'wykorzystuje wirtualizację systemu plików i rejestru systemu Windows',
        'correct': true,
      },
      {
        'text':
          'jest rodzajem kwarantanny dla potencjalnie zainfekowanych aplikacji, przetrzymywanych tam zanim antywirus otrzyma z chmury ostateczny rezultat analizy behawioralnej podejrzanego kodu',
        'correct': false,
      },
    ],
  },
  {
    'text': '36. Które z poniższych cech prawidłowo opisują protokół IPsec?',
    'answers': [
      {
        'text':
          'może działać z uwierzytelnianiem stron dokumentowanym tylko przez ESP',
        'correct': false,
      },
      {
        'text': 'może działać w trybie tylko z ochroną integralności przez ESP',
        'correct': true,
      },
      {
        'text':
          'może działać z uwierzytelnianiem stron dokumentowanym tylko przez AH',
        'correct': false,
      },
      {
        'text': 'może działać w trybie tylko z ochroną integralności przez AH',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '38. Które z poniższych algorytmów kryptograficznych mogą zostać wykorzystane w sieci VPN do szyfrowania transmisji przez protokół SSL/TLS lub IPsec:',
    'answers': [
      { 'text': 'RSA', 'correct': false },
      { 'text': 'ECDH', 'correct': false },
      { 'text': 'AES', 'correct': true },
      { 'text': 'DH', 'correct': false },
    ],
  },
  {
    'text': '39. Które z poniższych cech prawidłowo opisują protokół IKE?',
    'answers': [
      {
        'text': 'umożliwia zmianę kluczy szyfrowania protokołu IPsec ESP',
        'correct': true,
      },
      { 'text': 'uwierzytelnia sesje SA protokołu IPsec', 'correct': true },
      {
        'text': 'negocjuje parametry sesji SA protokołu IPsec',
        'correct': true,
      },
      {
        'text': 'umożliwia zmianę kluczy szyfrowania protokołu IPsec AH',
        'correct': false,
      },
    ],
  },
  {
    'text': '40. Tunele OpenVPN:',
    'answers': [
      { 'text': 'stosują protokół ESP do szyfrowania ruchu', 'correct': false },
      { 'text': 'stosują protokół AH do szyfrowania ruchu', 'correct': false },
      { 'text': 'stosują protokół TLS do szyfrowania ruchu', 'correct': true },
      {
        'text': 'stosują protokół ISAKMP do uwierzytelniania ruchu',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '41. Które z poniższych słów kluczowych mogą być prawidłowym "celem" w regule iptables dla łańcucha OUTPUT?',
    'answers': [
      { 'text': 'DROP', 'correct': true },
      { 'text': 'FORWARD', 'correct': false },
      { 'text': 'XOR', 'correct': false },
      { 'text': 'ACCEPT', 'correct': true },
    ],
  },
  {
    'text':
      '43. Czym się różni twist od spawn w polityce tcp wrappera (np. w pliku hosts.allow)?',
    'answers': [
      {
        'text':
          'spawn służy do zapisywania wiadomości w logu lub wysyłania poczty, natomiast twist wysyła wiadomość i odmawia dostępu do usługi',
        'correct': false,
      },
      {
        'text':
          'oba polecenia użyte w hosts.allow kończą się odmową polecenia, ale twist dodatkowo zapisuje informację o tym w logu systemowym',
        'correct': false,
      },
      {
        'text':
          'twist przekierowuje połączenie do innej, określonej opcją usługi, podczas gdy spawn tworzy nowy proces wykonujący dowolne polecenie',
        'correct': false,
      },
      {
        'text':
          'spawn tworzy nowy proces wykonujący dane polecenie, natomiast twist wykonuje polecenie w ramach bieżącego procesu',
        'correct': true,
      },
    ],
  },
  {
    'text': '44. Co oznacza udział IPC$ i do czego jest wykorzystywany?',
    'answers': [
      {
        'text':
          'to udział służący w systemie Windows do zdalnego wywołania procedur (RPC)',
        'correct': true,
      },
      {
        'text':
          'to udział domyślny służący do zdalnej administracji systemem Windows',
        'correct': false,
      },
      {
        'text':
          'to udział administracyjny obejmujący wszystkie istniejące lokalne dyski',
        'correct': false,
      },
      {
        'text':
          'to udział kolejek POSIX IPC służący do lokalnej komunikacji między procesami',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '47. W których z poniższych przypadków rekalkulowana jest maska uprawnień ACL w systemie Linux:',
    'answers': [
      { 'text': 'gdy podamy opcję -m dla polecenia setfacl', 'correct': false },
      {
        'text':
          'przy zmianie uprawnień właściciela przy pomocy polecenia chmod',
        'correct': false,
      },
      {
        'text':
          'przy każdej zmianie uprawnień poleceniem setfacl, chyba że użyjemy opcji -n',
        'correct': true,
      },
      {
        'text':
          'przy dowolnej zmianie uprawnień danej kategorii praw (np. maska dla grupy modyfikowana jest przy modyfikacji praw dotyczących grupy)',
        'correct': false,
      },
    ],
  },
  {
    'text': '48. Domyślne udziały administracyjne w systemie Windows:',
    'answers': [
      { 'text': 'dostępne są tylko dla administratora', 'correct': true },
      {
        'text': 'są tworzone automatycznie przy instalacji systemu',
        'correct': true,
      },
      { 'text': 'nie mogą być usunięte', 'correct': false },
      { 'text': 'mogą być usunięte', 'correct': true },
    ],
  },
  {
    'text': '50. Model kontroli dostępu MIC zabrania podmiotowi o etykiecie P:',
    'answers': [
      { 'text': 'zapisu obiektu o wyższej etykiecie niż P', 'correct': true },
      { 'text': 'odczytu obiektu o niższej etykiecie niż P', 'correct': true },
      { 'text': 'zapisu obiektu o niższej etykiecie niż P', 'correct': false },
    ],
  },
  {
    'text':
      '51. Wykorzystanie TCP Wrappera do ochrony określonej usługi jest możliwe:',
    'answers': [
      {
        'text':
          'jeśli program serwera usługi korzysta z biblioteki libwrap.so i sam czyta politykę TCP Wrappera',
        'correct': true,
      },
      {
        'text':
          'automatycznie po definicji polityki (host_access), bowiem TCP Wrapper jest zintegrowany z systemem operacyjnym',
        'correct': false,
      },
      {
        'text':
          'w przypadku przekazania nawiązywanego przez klienta usługi połączenia do demona TCP Wrappera zamiast do serwera obsługującego tę usługę',
        'correct': true,
      },
      {
        'text':
          'dopiero po skonfigurowaniu iptables do przekierowania ruchu na port nasłuchującego superserwera xinetd',
        'correct': false,
      },
    ],
  },
  {
    'text': '52a. Strumień ADS:',
    'answers': [
      {
        'text':
          'jest częścią nagłówka pliku dołączaną zawsze przez system Windows podczas operacji pakowania do archiwum lub udostępniania w sieci',
        'correct': false,
      },
      {
        'text':
          'jest wykorzystywany przez mechanizm informujący o stopniu zaufania do pliku (określający jego pochodzenie przez wpis ZoneId)',
        'correct': true,
      },
      {
        'text':
          'pozwala związać z dowolnym plikiem lub katalogiem dowolne (zarówno tekstowe, jak i binarne) dane',
        'correct': true,
      },
      {
        'text':
          'jest wykorzystywany przez procesy w systemie Windows do informowania o błędach wykonania (tzw. metainformacje)',
        'correct': false,
      },
    ],
  },
  {
    'text': '52b. Mechanizm EFS:',
    'answers': [
      {
        'text':
          'zabezpiecza dostęp do treści poszczególnych plików zarówno w czasie działania systemu, jak i po jego wyłączeniu (at rest)',
        'correct': true,
      },
      {
        'text':
          'stosuje kryptografię asymetryczną do szyfrowania treści plików',
        'correct': false,
      },
      {
        'text':
          'realizuje full disc encyption w celu zabezpieczenia systemu operacyjnego przed niepowołanym uruchomieniem i dostępem',
        'correct': false,
      },
      { 'text': 'wymaga do swojego działania konta DRA', 'correct': false },
    ],
  },
  {
    'text':
      '54. Gdy w poleceniu iptables nie podamy celu reguły, przy pomocy opcji -j (np. -j REJECT), wówczas:',
    'answers': [
      {
        'text':
          'po dopasowaniu reguły iptables przerywa przetwarzanie, ale pakiet jest przepuszczany',
        'correct': false,
      },
      {
        'text': 'po dopasowaniu reguły iptables przetwarza kolejne reguły',
        'correct': true,
      },
      {
        'text':
          'używany jest cel domyślny dla danego łańcucha, tzw. polityka (ustawiana przy pomocy -P)',
        'correct': false,
      },
      {
        'text':
          'reguła zostanie odrzucona jako błędna, chyba że jest to modyfikacja wcześniej istniejącej reguły (przy pomocy opcji -R), kiedy to zostanie zastosowany taki cel, jaki był ustawiony dotychczas w tej regule',
        'correct': false,
      },
    ],
  },
  {
    'text': '55. Impersonation w systemie Windows to:',
    'answers': [
      {
        'text':
          'przypisanie tokenu bezpieczeństwa ogólnego przeznaczenia do konkretnego użytkownika stanowiącego instancję pewnego SID',
        'correct': false,
      },
      {
        'text':
          'rodzaj zdalnego ataku na system, w którym napastnik podszywa się pod jednego z użytkowników',
        'correct': false,
      },
      {
        'text':
          'przechwycenie tokenu bezpieczeństwa SID przez nieuprawnionego użytkownika',
        'correct': false,
      },
      {
        'text':
          'czasowe przejęcie przez proces (wątek) uprawnień innego podmiotu',
        'correct': true,
      },
    ],
  },
  {
    'text': '56. Hasła użytkowników systemu Windows są przechowywane:',
    'answers': [
      { 'text': 'w rejestrze systemowym', 'correct': false },
      { 'text': 'w bazie SAM na dysku', 'correct': true },
      {
        'text': 'w formie nieodwracalnego wyniku funkcji mieszającej',
        'correct': true,
      },
      {
        'text':
          'w pliku shadow zaszyfrowanym kluczem RSA (SYSKEY), do którego dostęp ma tylko administrator systemu',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '57. W poleceniu: iptables -I INPUT -p icmp --icmp-type echo-request -m recent --name "ping" --set nazwa "ping":',
    'answers': [
      {
        'text':
          'jest to komentarz, pozwalający na szybką identyfikację reguły w przyszłości (np. w celu modyfikacji lub skasowania)',
        'correct': false,
      },
      {
        'text':
          'określa ten z ostatnio inicjowanych modułów filtracji (łańcuchów), który teraz będzie przechwytywał wskazane pakiety',
        'correct': false,
      },
      {
        'text':
          'identyfikuje konkretne statystyki, które później można wykorzystać do dalszej selekcji ruchu',
        'correct': true,
      },
      {
        'text':
          'definiuje nazwę pliku, który zawierać będzie informacje o ruchu pakietów do bieżącej reguły zapory',
        'correct': false,
      },
    ],
  },
  {
    'text': '58. Serwer OpenVPN umożliwia uwierzytelnianie klientów poprzez:',
    'answers': [
      { 'text': 'klucze kryptograficzne', 'correct': true },
      { 'text': 'hasła użytkowników', 'correct': false },
      { 'text': 'certyfikaty X.509', 'correct': true },
      { 'text': 'protokół Kerberos', 'correct': false },
      {
        'text': 'biometrycznie, poprzez analizę długości rzutu beretem',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '59. Po uruchomieniu Notatnika na niskim poziomie integralności, może on zapisywać pliki:',
    'answers': [
      {
        'text':
          'tylko w katalogach o przypisanym poziomie integralności co najwyżej niskim, np. %userprofile%/AppData/LocalLow',
        'correct': true,
      },
      {
        'text':
          'tylko w katalogach o przypisanym poziomie integralności co najmniej niskim, np. %userprofile%/Documents',
        'correct': false,
      },
      { 'text': 'nigdzie', 'correct': false },
      {
        'text': 'tylko w katalogu z danymi tymczasowymi, np. %systemroot%/Temp',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '62. Dodanie klucza wygenerowanego dla nowego agenta DRA, do istniejącego wcześniej zaszyfrowanego pliku, można uzyskać:',
    'answers': [
      {
        'text':
          'automatycznie, poprzez otwarcie tego pliku przez nowego agenta DRA',
        'correct': false,
      },
      {
        'text':
          'automatycznie, przy pierwszym otwarciu tego pliku przez dowolnego administratora',
        'correct': false,
      },
      {
        'text':
          'samoczynnie, przy okazji pierwszego dostępu do pliku kogoś mogącego odszyfrować ten plik',
        'correct': false,
      },
      { 'text': 'wydając polecenie cipher /u', 'correct': true },
    ],
  },
  {
    'text': '64. Uprawnienia domyślne na liście POSIX ACL nadawane są:',
    'answers': [
      {
        'text':
          'jedynie plikom wykonywalnym w celu uściślenia jakie uprawnienia mają mieć pliki tworzone w czasie działania tych programów',
        'correct': false,
      },
      {
        'text':
          'jedynie katalogom w celu inicjowania list ACL nowo tworzonym plikom',
        'correct': true,
      },
      {
        'text':
          'plikom i katalogom w celu określenia uprawnień w przypadku braku pasującego wpisu ACE',
        'correct': false,
      },
      {
        'text':
          'plikom i katalogom w celu określenia ACL w przypadku ich kopiowania lub przenoszenia do innego katalogu',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '65. Które z poniższych zdarzeń są efektami braku wirtualizacji danego klucza rejestru systemu Windows?',
    'answers': [
      {
        'text':
          'operacja zapisu wartości parametrów tego klucza przez proces nie posiadający uprawnienia zapisu kończy się powodzeniem',
        'correct': false,
      },
      {
        'text':
          'operacja zapisu wartości parametrów tego klucza przez proces posiadający uprawnienie zapisu kończy się błędem',
        'correct': false,
      },
      {
        'text':
          'operacja zapisu wartości parametrów tego klucza przez proces nie posiadający uprawnienia zapisu kończy się powodzeniem',
        'correct': false,
      },
      {
        'text':
          'operacja zapisu wartości parametrów tego klucza przez proces nie posiadający uprawnienia zapisu kończy się błędem',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '66. Z jaką inną opcją polityki silnych haseł ma bezpośredni związek ilość haseł pamiętanych w historii?',
    'answers': [
      { 'text': 'maksymalny okres ważności hasła', 'correct': false },
      { 'text': 'minimalny okres ważności', 'correct': true },
      { 'text': 'minimalna długość hasła', 'correct': false },
    ],
  },
  {
    'text':
      '67. Jak modyfikowana jest maska uprawnień POSIX ACL przy zmianie uprawnień do danego pliku:',
    'answers': [
      {
        'text':
          'nowa maska jest alternatywą bitową uprawnień nazwanych użytkowników, grupy i nazwanych grup',
        'correct': true,
      },
      {
        'text':
          'nowa maska jest alternatywą bitową starej maski i wszystkich uprawnień nowo nadanych przez setfacl',
        'correct': false,
      },
      {
        'text':
          'nowa maska jest iloczynem logicznym starej maski i wszystkich uprawnień nowo nadanych przez setfacl',
        'correct': false,
      },
      {
        'text':
          'nowa maska jest alternatywą bitową wszystkich uprawnień danego pliku (właściciela, grupy, pozostałych, nazwanych użytkowników, nazwanych grup)',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '69. Kolejność sprawdzania reguł polityki przez TCP Wrappera (pomijajac opcje only_from oraz no_access) jest następująca:',
    'answers': [
      {
        'text':
          'najpierw hosts.allow, potem hosts.deny, do odnalezienia pasującej reguły',
        'correct': true,
      },
      {
        'text':
          'sprawdzane są wszystkie reguły i jeżeli żadna z nich nie kończy się DENY, przyznawany jest dostęp',
        'correct': false,
      },
      {
        'text':
          'najpierw hosts.deny, potem hosts.allow, do odnalezienia pierwszej pasującej reguły',
        'correct': false,
      },
      {
        'text':
          'sprawdzane są wszystkie reguły i jeżeli żadna z nich nie kończy się DENY, a chociaż jedna kończy się ALLOW, przyznawany jest dostęp',
        'correct': false,
      },
    ],
  },
  {
    'text': '70. Ustawienia protokołu ESP w systemie Windows umożliwiają:',
    'answers': [
      {
        'text':
          'przesyłanie niezaszyfrowanego pakietu zabezpieczonego przed modyfikacją przy pomocy kryptograficznych funkcji mieszających',
        'correct': true,
      },
      {
        'text':
          'komunikację w trybie transportowym (bezpośrednim, host-to-host)',
        'correct': true,
      },
      {
        'text': 'komunikację w trybie tunelowym (net-to-net)',
        'correct': true,
      },
      {
        'text':
          'ustanowienie bezpiecznego kanału do zarządzania asocjacją IPsec',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '71. Mechanizm iptables może dokonywać wyboru reguł filtracji dla danego pakietu przez:',
    'answers': [
      {
        'text':
          'zasadę pierwszego dopasowania i zawsze przerywa szukanie przy pierwszym dopasowaniu',
        'correct': false,
      },
      {
        'text':
          'zasadę najlepszego dopasowania (najbardziej szczegółowa reguła)',
        'correct': false,
      },
      {
        'text':
          'zasadę pierwszego dopasowania, ale niekoniecznie przerywa szukanie przy pierwszym dopasowaniu',
        'correct': true,
      },
      {
        'text':
          'zasadę określoną w polityce danego łańcucha (np. BESTMATCH, FIRSTMATCH)',
        'correct': false,
      },
    ],
  },
  {
    'text': '72. Wirtualizacja rejestru w systemie Windows:',
    'answers': [
      {
        'text': 'chroni konfigurację systemu przed niepożądanymi zmianami',
        'correct': true,
      },
      {
        'text':
          'pozwala aplikacji 32-bitowej na modyfikację obszarów rejestru, do których aplikacja nie ma prawa zapisu',
        'correct': false,
      },
      { 'text': 'dotyczy wszystkich gałęzi rejestru', 'correct': false },
      {
        'text':
          'jest mechanizmem koniecznym do uruchomienia wirtualnych systemów Windows',
        'correct': false,
      },
    ],
  },
  {
    'text': '73. Tunele IPsec:',
    'answers': [
      { 'text': 'stosują protokół TLS do szyfrowania ruchu', 'correct': false },
      { 'text': 'stosują protokół AH do szyfrowania ruchu', 'correct': false },
      { 'text': 'stosują protokół ESP do szyfrowania ruchu', 'correct': true },
      {
        'text': 'stosują protokół AH do uwierzytelniania stron tunelu',
        'correct': false,
      },
    ],
  },
  {
    'text': '75. Agent DRA w systemie Windows to:',
    'answers': [
      {
        'text':
          'administrator systemu Windows, któremy przypisano prawo tworzenia strumieni ADS',
        'correct': false,
      },
      {
        'text':
          'lokalny administrator stacji roboczej w środowisku domenowym mogący robić kopie zapasowe',
        'correct': false,
      },
      { 'text': 'główny administrator domeny (serwera AD)', 'correct': false },
      {
        'text':
          'konto pozwalające na dostęp do plików zaszyfrowanych przez EFS',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '76. Które z poniższych twierdzeń dotyczących POSIX ACL są prawdziwe?',
    'answers': [
      {
        'text':
          'w momencie tworzenia katalogu jego uprawnienia ACL kopiowane są z domyślnych uprawnień (Default ACL) folderu nadrzędnego z wykluczeniem uprawnienia do wykonywania',
        'correct': false,
      },
      {
        'text':
          'w momencie tworzenia pliku jego uprawnienia domyślne (Default ACL) zostają odziedziczone z folderu nadrzędnego',
        'correct': false,
      },
      {
        'text':
          'w momencie tworzenia pliku jego uprawnienia ACL kopiowane są z domyślnych uprawnień (Default ACL) folderu nadrzędnego z wykluczeniem uprawnienia do wykonywania',
        'correct': true,
      },
      {
        'text':
          'w momencie tworzenia katalogu jego uprawnienia domyślne (Default ACL) zostają odziedziczone z folderu nadrzędnego',
        'correct': true,
      },
    ],
  },
  {
    'text': '84. Wskaż cechy SNAT:',
    'answers': [
      {
        'text': 'wymaga utrzymywania listy aktywnych translacji',
        'correct': true,
      },
      { 'text': 'ukrywa rzeczywisty adres nadawcy pakietu', 'correct': true },
      {
        'text':
          'może być pomyślnie wykonane pośrodku tunelu VPN zarówno w trybie tunelowym jak i transportowym',
        'correct': false,
      },
      {
        'text':
          'może być pomyślnie wykonane pośrodku tunelu VPN tylko w trybie transportowym',
        'correct': true,
      },
      {
        'text': 'wymaga uwierzytelnienia stron przed zestawieniem połączenia',
        'correct': false,
      },
      {
        'text':
          'pozwala uniknąć powtórnego sprawdzania reguł filtracji dla ruchu zweryfikowanego uprzednio',
        'correct': false,
      },
      {
        'text': 'dokonuje podmiany zarówno adresu jak i numeru portu',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '86. Jak zachowa się system kontroli ACL standardu POSIX w przypadku użytkownika U należącego do grupy G i wpisanego na liście ACL obiektu p, jeśli ani U ani G nie mają jawnie przydzielonego prawa r, ale kategoria "wszyscy użytkownicy" (others) takie uprawnienie do obiektu p posiada:',
    'answers': [
      {
        'text':
          'prawo do obiektu p nie zostanie efektywnie przyznane, ale U odziedziczy je w głąb, jeśli p jest katalogiem',
        'correct': false,
      },
      {
        'text':
          'prawo r do obiektu p zostanie efektywnie przyznane bezwarunkowo',
        'correct': false,
      },
      {
        'text':
          'prawo r do obiektu p zostanie efektywnie przyznane, o ile U jest właścicielem p',
        'correct': false,
      },
      {
        'text': 'prawo r do obiektu p nie zostanie efektywnie przyznane',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '90. Separację środowiska wykonania poprzez wirtualizację (jądra) systemu operacyjnego oferuje:',
    'answers': [
      { 'text': 'Trusted Execution Environment (TEE)', 'correct': false },
      { 'text': 'funkcja systemowa chroot()', 'correct': false },
      { 'text': 'Address Space Layout Randomization (ASLR)', 'correct': false },
      {
        'text': 'Windows Virtualization-Based Security (VBS)',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '92. Określ jakie potencjalne zagrożenia dla bezpieczeństwa niesie funkcja CreateRemotethread():',
    'answers': [
      {
        'text':
          'wywołanie zdalnych procedur (RPC) bez kontroli jądra zdalnego systemu operacyjnego',
        'correct': false,
      },
      {
        'text':
          'wykonanie nieautoryzowanych operacji podszywając się pod autoryzowany proces (obejście autoryzacji)',
        'correct': true,
      },
      {
        'text':
          'wstrzyknięcie złośliwego kodu do przestrzeni adresowej innego procesu w systemie operacyjnym',
        'correct': true,
      },
      {
        'text':
          'nie uwierzytelniony dostęp do komunikacji sieciowej poniżej warstwy transportowej',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '94. Które z poniższych protokołów służą realizacji kryptograficznych tuneli wirtualnych z ochroną poufności:',
    'answers': [
      { 'text': 'PEM', 'correct': false },
      { 'text': 'ESP', 'correct': true },
      { 'text': 'TLS', 'correct': true },
      { 'text': 'S/MIME', 'correct': false },
      { 'text': 'IPsec', 'correct': true },
      { 'text': 'SSL', 'correct': true },
    ],
  },
  {
    'text':
      '95. Wskaż cechy filtracji kontekstowej (SPF) realizowanej przez zapory sieciowe:',
    'answers': [
      {
        'text':
          'pozwala uniknąć niepotrzebnego sprawdzania reguł dla pakietów powracających w ruchu zweryfikowanym w stronę przeciwną',
        'correct': true,
      },
      { 'text': 'zapora utrzymuje listę aktywnych połączeń', 'correct': true },
      {
        'text': 'dopasowuje pakiety do zapamiętanej historii komunikacji',
        'correct': true,
      },
      {
        'text': 'historia komunikacji nie ma wpływu na decyzje zapory',
        'correct': false,
      },
      {
        'text': 'pozwala na dynamiczne modyfikacje reguł filtracji',
        'correct': false,
      },
    ],
  },
  {
    'text': '96. Które stwierdzenie poprawnie opisują protokół IKE w IPsec:',
    'answers': [
      { 'text': 'realizuje uwierzytelnianie stron', 'correct': true },
      { 'text': 'realizuje podpis cyfrowy pakietów IP', 'correct': false },
      { 'text': 'korzysta z UDP', 'correct': true },
      { 'text': 'korzysta z ICMP', 'correct': false },
      {
        'text': 'realizuje negocjację algorytmów szyfrujących',
        'correct': true,
      },
      {
        'text': 'realizuje wymianę kluczy metodą Diffiego-Hellmana',
        'correct': true,
      },
    ],
  },
  {
    'text': '98. Firewalking to:',
    'answers': [
      {
        'text': 'połączenia zapór filtrujących ruch sieciowy z usługami proxy',
        'correct': false,
      },
      {
        'text':
          'technika odkrywania istnienia zapory sieciowej i otwartych na niej portów',
        'correct': true,
      },
      {
        'text': 'szeregowe połączenia zapór sieciowych typu proxy',
        'correct': false,
      },
      {
        'text': 'kaskadowe połączenia zapór sieciowych filtrujących pakiety',
        'correct': false,
      },
    ],
  },
  {
    'text': '103. Użycie IPsec + IKE wprost chroni przed atakiem:',
    'answers': [
      { 'text': 'name spoofing', 'correct': false },
      { 'text': 'ARP cache spoofing', 'correct': false },
      { 'text': 'TCP spoofing', 'correct': true },
      { 'text': 'session hijacking', 'correct': true },
      { 'text': 'network sniffing', 'correct': true },
      { 'text': 'ARP spoofing', 'correct': false },
    ],
  },
  {
    'text':
      '106. Wskaż prawidłowe stwierdzenia dotyczące metod uwierzytelniania systemów operacyjnych MS Windows w środowisku sieciowym:',
    'answers': [
      { 'text': 'NTLM jest bezpieczniejszy niż LM', 'correct': true },
      { 'text': 'Kerberos jest bezpieczniejszy niż LM', 'correct': true },
      {
        'text': 'Kerberos jest dostępny tylko w środowisku domenowym',
        'correct': true,
      },
      { 'text': 'LM jest bezpieczniejszy niż NTLM', 'correct': false },
    ],
  },
  {
    'text':
      '108. Następująca reguła filtracji zapory sieciowej: od *.*.*.* -> do 1.1.1.1, port źródłowy *, port docelowy 80, protokół TCP, flagi ACK=0, reakcja odrzuć:',
    'answers': [
      {
        'text':
          'blokuje wszelkie połączenia nawiązywane z serwera www o dowolnym adresie',
        'correct': false,
      },
      {
        'text':
          'blokuje wszelkie połączenia nawiązywane z serwera www o adresie 1.1.1.1',
        'correct': true,
      },
      {
        'text':
          'blokuje wszelkie połączenia nawiązywane z serwerem www o adresie 1.1.1.1',
        'correct': false,
      },
      {
        'text':
          'blokuje wszelkie połączenia nawiązywane z serwerem www o dowolnym adresie',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '109. Które z poniższych protokołów służą realizacji kryptograficznych tuneli wirtualnych z ochroną poufności?',
    'answers': [
      { 'text': 'PGP', 'correct': false },
      { 'text': 'ESP', 'correct': true },
      { 'text': 'X.400', 'correct': false },
      { 'text': 'AH', 'correct': false },
    ],
  },
  {
    'text':
      '115. Wskaż cechy zapory sieciowej zrealizowanej poprzez Komputer-Twierdzę (Bastion Host):',
    'answers': [
      {
        'text':
          'dla ruchu z zewnątrz zapora "przykrywa" sobą całą sieć wewnętrzną',
        'correct': true,
      },
      {
        'text':
          'dla ruchu od wewnątrz zapora "przykrywa" sobą cały świat zewnętrzny',
        'correct': true,
      },
      { 'text': 'w zaporze nie jest realizowany routing', 'correct': true },
      {
        'text': 'komunikacja zachodzi wyłącznie przez usługi proxy',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '117. Które z poniższych technologii sprzętowych umożliwiają separację środowiska wykonawczego aplikacji poprzez wirtualizację całości bądź części systemu operacyjnego (np. jądra systemu):',
    'answers': [
      { 'text': 'TEE (Trusted Execution Environment)', 'correct': true },
      { 'text': 'VBS (Virtualization-Based Security)', 'correct': true },
      { 'text': 'ARM TrustZone', 'correct': true },
      { 'text': 'SSL (Secure Socket Layer)', 'correct': false },
    ],
  },
  {
    'text':
      '125. Które z poniższych protokołów służą realizacji kryptograficznych tuneli wirtualnych z ochroną integralności?',
    'answers': [
      { 'text': 'TLS', 'correct': true },
      { 'text': 'S/MIME', 'correct': false },
      { 'text': 'AH', 'correct': true },
      { 'text': 'ESP', 'correct': true },
    ],
  },
  {
    'text':
      '127. Wskaż rodzaje adresów, które zapora sieciowa dokonująca translacji NAT powinna filtrować w pakietach przychodzących od strony zewnętrznej sieci publicznej:',
    'answers': [
      { 'text': 'dowolne prywatne IP, w polu źródłowym', 'correct': true },
      { 'text': 'dowolne prywatne IP, w polu docelowym', 'correct': false },
      {
        'text': 'adresy wykorzystywane wewnątrz, w polu źródłowym',
        'correct': true,
      },
      {
        'text': 'adresy wykorzystywane wewnątrz, w polu docelowym',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '128. Do przechowywania danych uwierzytelniających w systemie MS Windows aplikacje mogą skorzystać z:',
    'answers': [
      { 'text': 'Winlog API', 'correct': false },
      { 'text': 'Data Protection API (DPAPI)', 'correct': true },
      { 'text': 'Credential Manager API', 'correct': true },
      { 'text': 'Generic Security Service API (GSSAPI)', 'correct': false },
    ],
  },
  {
    'text':
      '129. Następująca reguła filtracji zapory sieciowej: od *.*.*.* -> do 1.1.1.1, port źródłowy *, port docelowy 80, protokół TCP, flagi SYN=1, reakcja odrzuć:',
    'answers': [
      {
        'text':
          'blokuje wszelkie połączenia nawiązywane z serwera www o dowolnym adresie',
        'correct': false,
      },
      {
        'text':
          'blokuje wszelkie połączenia nawiązywane z serwerem www o dowolnym adresie',
        'correct': false,
      },
      {
        'text':
          'blokuje wszelkie połączenia nawiązywane z serwerem www o adresie 1.1.1.1',
        'correct': true,
      },
      {
        'text':
          'blokuje wszelkie połączenia nawiązywane z serwera www o adresie 1.1.1.1',
        'correct': false,
      },
    ],
  },
  {
    'text': '132. Wskaż cechy DNAT:',
    'answers': [
      {
        'text':
          'pozwala uniknąć powtórnego sprawdzania reguł filtracji dla ruchu zweryfikowanego uprzednio',
        'correct': false,
      },
      { 'text': 'ukrywa rzeczywisty adres odbiorcy pakietu', 'correct': true },
      {
        'text':
          'może być pomyślnie wykonanie pośrodku tunelu VPN tylko w trybie transportowym//tunelowym',
        'correct': true,
      },
      { 'text': 'ukrywa rzeczywisty adres nadawcy pakietu', 'correct': false },
    ],
  },
  {
    'text':
      '133. Wskaż cechy filtracji bezstanowej realizowanej przez zapory sieciowe:',
    'answers': [
      { 'text': 'zapora utrzymuje listę aktywnych połączeń', 'correct': false },
      {
        'text':
          'pozwala uniknąć niepotrzebnego sprawdzania reguł dla pakietów powracających w ruchu zweryfikowanym w stronę przeciwną',
        'correct': false,
      },
      {
        'text': 'dopasowuje pakiety do zapamiętanej historii komunikacji',
        'correct': false,
      },
      {
        'text': 'historia komunikacja nie ma wpływu na decyzje zapory',
        'correct': true,
      },
      {
        'text': 'wymaga sprawdzania reguł dla każdego pakietu',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '140. Które z poniższych protokołów służą realizacji kryptograficznych tuneli wirtualnych:',
    'answers': [
      { 'text': 'TLS', 'correct': true },
      { 'text': 'LDAP', 'correct': false },
      { 'text': 'X.400', 'correct': false },
      { 'text': 'L2TP', 'correct': true },
      { 'text': 'IPsec', 'correct': true },
      { 'text': 'SSL', 'correct': true },
    ],
  },
  {
    'text': '147. Mechanizm ACL:',
    'answers': [
      {
        'text': 'oferuje niezaprzeczalność nadania wiadomości',
        'correct': false,
      },
      {
        'text': 'jest narzędziem kontroli dostępu do zasobów',
        'correct': true,
      },
      {
        'text': 'oferuje niezaprzeczalność odbioru wiadomości',
        'correct': false,
      },
      { 'text': 'wyróżnia systemy MAC od DAC', 'correct': false },
    ],
  },
  {
    'text':
      '149. Jaki rodzaj filtracji umożliwia podejmowanie decyzji o filtracji pakietów z uwzględnieniem stanu sesji do której przynależą?',
    'answers': [
      { 'text': 'filtry bezstanowe', 'correct': false },
      { 'text': 'filtry statyczne', 'correct': false },
      { 'text': 'filtry kontekstowe', 'correct': false },
      { 'text': 'Stateful Packet Filtering', 'correct': true },
    ],
  },
  {
    'text': '153. Które określenie poprawnie opisuje protokół IKE?',
    'answers': [
      { 'text': 'oferuje uwierzytelnianie stron', 'correct': true },
      { 'text': 'korzysta z ICMP', 'correct': false },
      { 'text': 'korzysta z UDP', 'correct': true },
      { 'text': 'oferuje negocjację algorytmów szyfrujących', 'correct': true },
    ],
  },
  {
    'text':
      '154. Przed którymi atakami chroni poprawnie nawiązana sesja VPN (IPsec lub TLS):',
    'answers': [
      { 'text': 'TCP spoofing', 'correct': true },
      { 'text': 'SQLi', 'correct': false },
      { 'text': 'DNS spoofing', 'correct': false },
      { 'text': 'ARP spoofing', 'correct': false },
    ],
  },
  {
    'text':
      '156. Wskaż kto może rozszyfrować plik zaszyfrowany mechanizmem EFS:',
    'answers': [
      {
        'text': 'każdy agent DRA istniejący w momencie deszyfrowania pliku',
        'correct': false,
      },
      { 'text': 'właściciel pliku', 'correct': true },
      { 'text': 'administrator', 'correct': false },
      {
        'text': 'każdy DRA istniejący w momencie szyfrowania pliku',
        'correct': true,
      },
    ],
  },
  {
    'text': '157. Mechanizm Lock-and-Key:',
    'answers': [
      {
        'text': 'wymaga uwierzytelnienia użytkownika, np. za pomocą RADIUS-a',
        'correct': false,
      },
      {
        'text':
          'automatycznie blokuje stacje niespełniające wymagań polityki bezpieczeństwa',
        'correct': false,
      },
      {
        'text':
          'może być wykorzystywany do tymczasowego uzyskania uprzywilejowanego dostępu do sieci wewnętrznej z zewnątrz',
        'correct': true,
      },
      {
        'text': 'służy do translacji reguł filtracji z jednej zapory na inną',
        'correct': false,
      },
    ],
  },
  {
    'text': '158. Protokół SSL/TLS oferuje:',
    'answers': [
      {
        'text': 'uwierzytelnianie obustronne uczestników komunikacji',
        'correct': true,
      },
      {
        'text': 'szyfrowanie transmisji na poziomie warstwy sesji OSI',
        'correct': true,
      },
      { 'text': 'uwierzytelnianie SSO', 'correct': false },
      {
        'text': 'szyfrowanie transmisji na poziomie warstwy transportowej OSI',
        'correct': false,
      },
    ],
  },
  {
    'text': '167. Skrót ACL oznacza:',
    'answers': [
      { 'text': 'Added Control List', 'correct': false },
      { 'text': 'Access Control List', 'correct': true },
      { 'text': 'Lista uprawnień nadanych', 'correct': false },
      { 'text': 'Lista kontroli dostępu', 'correct': false },
    ],
  },
  {
    'text': '170. TUN/TAP to:',
    'answers': [
      { 'text': 'rozszerzenie programu OpenVPN', 'correct': false },
      {
        'text': 'sterownik działający tylko na systemach Windows',
        'correct': false,
      },
      {
        'text': 'sterownik działający tylko na systemach Linux',
        'correct': false,
      },
      { 'text': 'coś takiego nie istnieje', 'correct': false },
      {
        'text': 'komponent pozwalający tworzyć wirtualne interfejsy sieciowe',
        'correct': true,
      },
    ],
  },
  {
    'text': '187. IPsec ESP umożliwia zapewnienie:',
    'answers': [
      {
        'text':
          'autentyczności treści datagramu przy wykorzystaniu algorytmu MD5',
        'correct': false,
      },
      {
        'text':
          'autentyczności treści datagramu przy wykorzystaniu algorytmu 3DES',
        'correct': false,
      },
      {
        'text': 'poufności treści datagramu w trybie tunelowym',
        'correct': true,
      },
      {
        'text': 'poufności treści datagramu w trybie transportowym',
        'correct': true,
      },
      {
        'text': 'tylko autentyczności treści datagramu, nie poufności',
        'correct': false,
      },
      {
        'text': 'tylko poufności treści datagramu, nie autentyczności',
        'correct': true,
      },
      {
        'text':
          'poufności i/lub autentyczności treści datagramu, w trybie synchronicznym',
        'correct': false,
      },
      {
        'text':
          'poufności i/lub autentyczności treści datagramu, w trybie tunelowym',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '188. Jaki mechanizm może wykorzystać administrator do dynamicznego uaktywnienia specjalnie przygotowanych reguł filtracji umożliwiających obejście ograniczeń narzuconych na normalny ruch sieciowy?',
    'answers': [
      { 'text': 'zamek-i-klucz', 'correct': true },
      { 'text': 'dynamiczny skaner portów', 'correct': false },
      { 'text': 'sniffer dynamiczny', 'correct': false },
      { 'text': 'NIDS lub HIPS', 'correct': false },
    ],
  },
  {
    'text': '194. Wykorzystując stanowość zapory sieciowej możemy określić:',
    'answers': [
      {
        'text':
          'odrzucić pakiety próbujące podszywać się pod rzekomo istniejące połączenia',
        'correct': true,
      },
      {
        'text': 'czy pakiet próbuje obejść nasz system bezpieczeństwa',
        'correct': false,
      },
      { 'text': 'czy połączenie jest już ustanowione', 'correct': true },
      { 'text': 'czy pakiet zawiera flagę ACK', 'correct': false },
    ],
  },
  {
    'text': '195. LMhash to:',
    'answers': [
      {
        'text': 'hasło administratora systemu zapisane w sposób jawny',
        'correct': false,
      },
      {
        'text':
          'hasła użytkowników w postaci skrótów (hashy) wykorzystywane przez Lan Managera',
        'correct': true,
      },
      {
        'text':
          'Lan Manager hash służący do identyfikacji systemu w sieci lokalnej',
        'correct': false,
      },
      { 'text': 'hash numeru seryjnego systemu Ms Windows', 'correct': false },
    ],
  },
  {
    'text': '196. Dziedziczenie uprawnień w systemie plików NTFS:',
    'answers': [
      {
        'text':
          'uprawnienia sa pobierane bezpośrednio z uprawnień obiektu wyższego',
        'correct': true,
      },
      {
        'text': 'może przenieść również na system plików FAT64',
        'correct': false,
      },
      { 'text': 'jest identycznie z systemem plików ext3', 'correct': false },
      { 'text': 'nie istnieje w tym systemie plików', 'correct': false },
    ],
  },
  {
    'text': '200. Mechanizm TCP Wrapper:',
    'answers': [
      {
        'text': 'pozwala ograniczać dostęp do usług uruchamianych przez xinetd',
        'correct': true,
      },
      {
        'text': 'pozwala blokować spam przychodzący do serwera SMTP',
        'correct': false,
      },
      {
        'text': 'pozwala szyfrować ruch TCP z użyciem protokołów TLS/SSL',
        'correct': false,
      },
      {
        'text':
          'powstał, aby wprowadzić silne uwierzytelnianie dla tzw. small services',
        'correct': false,
      },
    ],
  },
  {
    'text': '201. Tunel Net-to-Net to:',
    'answers': [
      {
        'text':
          'koncepcja połączenia dwóch lub więcej sieci, w której istnieją zestawione tunele między bramami dla każdej z sieci w sieci Internet',
        'correct': true,
      },
      {
        'text': 'bezpośrednie połączenie typu proxy dwóch sieci przez Internet',
        'correct': false,
      },
      {
        'text':
          'tunel zestawiany między systemami autonomicznymi w celu wymiany informacji o trasach routingu',
        'correct': false,
      },
      {
        'text': 'bezpośrednie połączenie dwóch lub więcej sieci przez Internet',
        'correct': false,
      },
    ],
  },
  {
    'text': '205. Skrót IKE oznacza:',
    'answers': [
      {
        'text': 'rodzaj algorytmów wymiany kluczy w FreeS/Wan',
        'correct': false,
      },
      {
        'text':
          'bardzo ważny element pakietu FreeS/Wan pozwalający tworzyć bezpieczne połączenie sterujące tunelami VPN',
        'correct': true,
      },
      { 'text': 'Information Key Exchange', 'correct': false },
      {
        'text': 'jeden z algorytmów szyfrowania w pakiecie FreeS/Wan',
        'correct': false,
      },
    ],
  },
  {
    'text': '206. Pakiet FreeS/Wan składa się z:',
    'answers': [
      {
        'text':
          'z trzech komponentów: łata na jądro KLIPS, demon PLUTO, zestaw skryptów',
        'correct': true,
      },
      { 'text': 'z dwóch protokołów: AH i ESP', 'correct': false },
      {
        'text':
          'z kilkunastu różnych algorytmów szyfrowania m.in. DES i 3DES oraz protokołu wymiany kluczy: ISAKMP',
        'correct': false,
      },
    ],
  },
  {
    'text': '207. Kryptografia oportunistyczna to:',
    'answers': [
      {
        'text':
          'nowy rodzaj szyfrowania, bardzo wydajny i nie do złamania w dzisiejszych czasach z użyciem obecnych maszyn obliczeniowych',
        'correct': false,
      },
      {
        'text':
          'automatyczny sposób negocjowania parametrów połączenia zaimplementowany w pakiecie FreeS/Wan',
        'correct': true,
      },
      {
        'text':
          'eksperymentalny projekt nowego rodzaju szyfrowania rozwijany na potrzeby amerykańskiej Agencji Bezpieczeństwa Narodowego',
        'correct': false,
      },
      {
        'text':
          'prosty rodzaj szyfrowania, nazwa "oportunistyczna" zaczerpnięta od francuskiego słowa: opportunisme oznaczającego "sprzyjający, dogodny"',
        'correct': false,
      },
    ],
  },
  {
    'text': '208. Narzędzie FreeS/Wan to:',
    'answers': [
      {
        'text':
          'łata na jądro implementująca funkcjonalność ISec plus zestaw skryptów do zarządzania tym narzędziem',
        'correct': false,
      },
      {
        'text':
          'program działający w przestrzeni użytkownika który posiada jeden plik konfiguracyjny zlokalizowany domyślnie: /etc/spiec',
        'correct': false,
      },
      {
        'text':
          'narzędzie w formie łaty na jądro systemu Linux wraz z zestawem skryptów zarządzających oraz demon pozwalający wymieniać klucze',
        'correct': true,
      },
      {
        'text':
          'narzędzie bardzo podobne do narzędzia Vtun służące do zestawiania połączeń VPN',
        'correct': false,
      },
    ],
  },
  {
    'text': '209. Tunel Host-to-host to:',
    'answers': [
      {
        'text':
          'połączenie punkt - punkt między dwoma hostami, ale tylko na czas transmisji zaszyfrowanej',
        'correct': true,
      },
      {
        'text': 'połaczenie peer-to-peer z rezerwacja pasma na calej',
        'correct': false,
      },
      {
        'text':
          'połączenie wykorzystujące już zestawione połączenie punkt-punkt dodające tylko szyfrowanie i uwierzytelnianie',
        'correct': false,
      },
    ],
  },
  {
    'text': '210. W jakich trybach może działać VPN:',
    'answers': [
      { 'text': 'ruch sieciowy tunelowy i uwierzytelniany', 'correct': false },
      {
        'text': 'ruch sieciowy nieszyfrowany ale uwierzytelniany',
        'correct': false,
      },
      {
        'text': 'ruch sieciowy szyfrowany ale nie uwierzytelniany',
        'correct': false,
      },
      { 'text': 'ruch sieciowy tunelowany/transportowany', 'correct': true },
      {
        'text': 'ruch sieciowy transportowany, szyfrowany i uwierzytelniany',
        'correct': false,
      },
    ],
  },
  {
    'text': '211. Skrót VPN to:',
    'answers': [
      {
        'text':
          'szczególny rodzaj sieci vlan ale rozciągającej się na kilka sieci lokalnych rozdzielonych Internetem',
        'correct': false,
      },
      { 'text': 'wirtualna sieć prywatna', 'correct': true },
      {
        'text':
          'dodatkowy model komunikacji wykorzystywany przez IPSec do zaufanych połączeń między urządzeniami sieciowymi takimi jak routery i switche, hosty',
        'correct': false,
      },
      {
        'text':
          'szkieletowa sieć w Internecie przeznaczona dla zastosowań korporacyjnych zapewniająca wysoki stopień bezpieczeństwa np. w przypadku transakcji między bankami albo filiami tego samego banku połączonych Internetem',
        'correct': false,
      },
    ],
  },
  {
    'text': '212. Translacja typu DNAT charakteryzuje się:',
    'answers': [
      {
        'text':
          'zamiana adresów źródłowych na inne (możliwe do wykorzystania na danym urządzeniu)',
        'correct': false,
      },
      { 'text': 'nie ma translacji typu DNAT', 'correct': false },
      { 'text': 'zamiana adresów docelowych na inne', 'correct': true },
      {
        'text':
          'zamiana adresu źródłowego z adresem docelowym w konkretnym pakiecie',
        'correct': false,
      },
    ],
  },
  {
    'text': '214. Ukrycie widoczności systemu Ms Win spowoduje:',
    'answers': [
      {
        'text': 'niedziałanie zdalnego logowania do systemu',
        'correct': false,
      },
      { 'text': 'niedziałanie udostępniania zasobów', 'correct': true },
      { 'text': 'ukrycie systemu przed innymi systemami', 'correct': false },
      {
        'text': 'ukrycie systemu tylko przed systemami typu Unix',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '217. Wskaż cechy filtracji bezstanowej realizowanej przez zapory sieciowe:',
    'answers': [
      {
        'text': 'dopasowuje pakiety do zapamiętanej historii komunikacji',
        'correct': false,
      },
      {
        'text':
          'pozwala uniknąć niepotrzebnego sprawdzania reguł dla pakietów powracających w ruchu zweryfikowanym w strone przeciwna',
        'correct': false,
      },
      {
        'text': 'wymaga sprawdzania reguł dla każdego pakietu',
        'correct': true,
      },
      {
        'text': 'historia komunikacji nie ma wpływu na decyzje zapory',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '223. Statyczne reguły filtracji (filtracja bezstanowa) nie radzą sobie z precyzyjna filtracja ruchu:',
    'answers': [
      {
        'text': 'HTTP, gdy serwer pracuje w trybie bezstanowym',
        'correct': false,
      },
      {
        'text': 'HTTP, gdy serwer pracuje w trybie stanowym',
        'correct': false,
      },
      { 'text': 'FTP, gdy serwer pracuje w trybie aktywnym', 'correct': true },
      { 'text': 'FTP, gdy serwer pracuje w trybie pasywnym', 'correct': false },
    ],
  },
  {
    'text': '238. Mechanizm ACL umożliwia:',
    'answers': [
      {
        'text': 'nadawanie praw (rwx) wielu użytkownikom i grupom',
        'correct': true,
      },
      { 'text': 'odtwarzanie zniszczonych plików', 'correct': false },
      {
        'text': 'nadawanie nowych praw (np. dopisywania) wielu użytkownikom',
        'correct': true,
      },
      { 'text': 'ustanowienie szyfrowania plików', 'correct': false },
    ],
  },
  {
    'text':
      '250. Które protokoły umożliwiają propagacje portów w tunelu kryptograficznym?',
    'answers': [
      { 'text': 'ESP', 'correct': false },
      { 'text': 'SSH', 'correct': true },
      { 'text': 'SSL', 'correct': true },
      { 'text': 'AH', 'correct': false },
    ],
  },
  {
    'text': '253. Ochronę SYSKEY wprowadzono w systemie MS Windows w celu:',
    'answers': [
      {
        'text': 'szyfrowania plików użytkowników w systemie NTFS',
        'correct': false,
      },
      {
        'text': 'wzmocnionego szyfrowania postaci hash haseł użytkowników',
        'correct': true,
      },
      {
        'text':
          'odszyfrowania plików przez systemowa usługę odzyskiwania plików',
        'correct': false,
      },
      {
        'text': 'szyfrowania plików systemowych w systemie NTFS',
        'correct': false,
      },
    ],
  },
  {
    'text': '256. Jakie komponenty tworzą każdą zaporę sieciowa?',
    'answers': [
      { 'text': 'dekoder ramek PDU', 'correct': true },
      { 'text': 'filtr pakietów', 'correct': true },
      { 'text': 'sniffer pakietów', 'correct': false },
      { 'text': 'skaner portów', 'correct': false },
    ],
  },
  {
    'text':
      '266. Jakie właściwości można ustawić w Zasadach haseł w systemie Windows?',
    'answers': [
      { 'text': 'złożoność haseł', 'correct': true },
      { 'text': 'maksymalna długość nazwy użytkownika', 'correct': false },
      { 'text': 'minimalna długość nazwy użytkownika', 'correct': false },
      {
        'text': 'włączenie szyfrowania AES haseł użytkowników',
        'correct': false,
      },
      { 'text': 'minimalna długość hasła użytkownika', 'correct': true },
    ],
  },
  {
    'text': '267. Systemowa zapora sieciowa w systemie Windows:',
    'answers': [
      {
        'text':
          'pozwala zestawiać tunel IPsec domyślnie szyfrując dane algorytmem 3DES',
        'correct': false,
      },
      { 'text': 'może monitorować parametry asocjacji IPsec', 'correct': true },
      {
        'text':
          'pozwala zestawiać tunel IPsec domyślnie szyfrując dane algorytmem AES',
        'correct': true,
      },
      {
        'text': 'może monitorować parametry asocjacji ISAKMP',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '268. Lokalna zapora sieciowa systemu Windows na stanowisku X zablokowała możliwość zdalnego odpytywania o dostępność X przy pomocy narzędzia ping, pozostawiając jednak możliwość zdalnego dostępu do serwera www w tym systemie. Mogła to osiągnąć poprzez:',
    'answers': [
      {
        'text': 'wyłączenie obsługi przychodzących komunikatów ICMP echo',
        'correct': true,
      },
      { 'text': 'odrzucanie całego ruchu ICMP', 'correct': false },
      {
        'text': 'zablokowanie komunikacji z siecią dla programu ping',
        'correct': false,
      },
      {
        'text':
          'wyłączenie ruchu IP na wszystkich interfejsach, ale pozostawienie dostępu do wskazanych portów TCP',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '269. Użytkownik U systemu Unix należący do grupy G1 nie ma wpisu na liście ACL do zasobu O w systemie plików. Jednak grupie G1 na liście ACL tego zasobu nadano prawa r i w, natomiast wszystkim pozostałym (others) - prawa r oraz x. Które efektywne uprawnienia do O posiada U? (U nie jest właścicielem O i nie należy do grupy zasobu O):',
    'answers': [
      { 'text': 'r', 'correct': true },
      { 'text': 'w', 'correct': true },
      { 'text': 'x', 'correct': false },
      { 'text': 'żadne', 'correct': false },
    ],
  },
  {
    'text':
      '270. Zasoby systemu operacyjnego MS Windows udostępnione poprzez SMB:',
    'answers': [
      {
        'text':
          'mogą mieć ograniczony dostęp do odczytu i/lub zapisu tylko dla wskazanych użytkowników',
        'correct': true,
      },
      { 'text': 'nazywa się udziałami', 'correct': true },
      { 'text': 'nazywa się portami', 'correct': false },
      {
        'text':
          'przy dostępie zdalnym zawsze wymagane jest logowanie (podawanie hasła)',
        'correct': false,
      },
      {
        'text':
          'tylko użytkownicy, którzy posiadają lokalne konto w systemie operacyjnym mogą uzyskać zdalny dostęp do zasobu',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '272. Kto może nadawać/modyfikować uprawnienia POSIX ACL danego obiektu w systemie plików:',
    'answers': [
      {
        'text': "właściciel obiektu, ale pod warunkiem, że posiada prawo 'w'",
        'correct': false,
      },
      {
        'text': "właściciel obiektu, niezależnie od posiadania prawa 'w'",
        'correct': true,
      },
      {
        'text': 'dowolny użytkownik posiadający prawo modyfikacji pliku',
        'correct': false,
      },
      { 'text': 'administrator (root)', 'correct': true },
    ],
  },
  {
    'text': '274. Wpisy ACE (na liście ACL) zabraniające dostępu:',
    'answers': [
      {
        'text':
          'występują tylko w przypadku zwirtualizowanych aplikacji w MS Windows',
        'correct': false,
      },
      { 'text': 'nie są dziedziczone wgłąb katalogu', 'correct': false },
      { 'text': 'występują tylko w POSIX ACL', 'correct': false },
      {
        'text': 'mają priorytet nad wpisami ACE przyznającymi dostęp',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '277. Czy zaszyfrowany plik w systemie MS Windows możemy współdzielić z innym użytkownikiem?',
    'answers': [
      {
        'text':
          'tylko pod warunkiem przekazania temu użytkownikowi swojego klucza prywatnego',
        'correct': false,
      },
      {
        'text':
          'tylko pod warunkiem przekazania temu użytkownikowi swojego klucza publicznego',
        'correct': false,
      },
      { 'text': 'nie jest to możliwe', 'correct': false },
      {
        'text': 'pod warunkiem posiadania certyfikatu EFS tego użytkownika',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '278. W jaki sposób można jednoznacznie określić, które konto w systemie operacyjnym MS Windows jest wbudowanym kontem administracyjnym?',
    'answers': [
      {
        'text':
          'Aktualnie nie ma jednego wbudowanego konta administracyjnego- każde konto użytkownika może posiadać takie uprawnienia po odpowiedniej konfiguracji',
        'correct': false,
      },
      {
        'text': 'konto takie ma zawsze nazwę "Administrator"',
        'correct': false,
      },
      {
        'text': 'część względna identyfikatora tego konta ma stałą wartość 500',
        'correct': true,
      },
      {
        'text': 'część względna identyfikatora tego konta ma stałą wartość 0',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '279. Co oznacza termin "asocjacja bezpieczeństwa" (ang.Security Association)?',
    'answers': [
      {
        'text':
          'Nazwa jednokierunkowego protokołu uwierzytelniania tuneli IPSec',
        'correct': false,
      },
      {
        'text':
          'Jest to zestaw parametrów zabezpieczonego połączenia niezbędny do poprawnej interpretacji danych płynących w tunelu VPN',
        'correct': true,
      },
      {
        'text':
          'Jest to wstępny proces zestawiania tunelu VPN, w którym negocjowane są parametry połączenia',
        'correct': false,
      },
      {
        'text':
          'Jest to nazwa polityki IPsec określające filtry pakietów poddawanych zabezpieczaniu',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '280. Które stwierdzenia dotyczące blokady konta w systemie Windows są nieprawdziwe:',
    'answers': [
      {
        'text':
          'próg blokady określa ilość kolejnych niepomyślnych prób logowania, po osiągnięciu której dostęp do konta będzie czasowo zablokowany',
        'correct': true,
      },
      {
        'text':
          'licznik prób logowania jest zerowany automatycznie po upływie czasu blokady konta',
        'correct': false,
      },
      {
        'text':
          'podczas blokady konta, kolejne logowanie będzie możliwe dopiero po wyzerowaniu licznika prób (np. przez administratora)',
        'correct': false,
      },
      {
        'text':
          'w czasie określonym długością okresu zerowania licznika prób logowania, użytkownik nie może podjąć więcej udanych prób logowania niż określa próg blokady',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '281. Zapora sieciowa lokalnego systemu na stanowisku X zablokowała możliwość zdalnego odpytywania o dostępności X przy pomocy narzędzia ping, pozostawiając jednak możliwość zdalnego dostępu do serwera www w tym systemie. Mogła to osiągnąć poprzez:',
    'answers': [
      {
        'text':
          'wyłączenie ruchu IP na wszystkich interfejsach, ale pozostawienie dostępu do wskazanych portów TCP',
        'correct': false,
      },
      {
        'text': 'zablokowanie komunikacji z siecią dla programu ping',
        'correct': false,
      },
      {
        'text': 'wyłączenie obsługi przychodzących komunikatów ICMP echo',
        'correct': true,
      },
      { 'text': 'odrzucenie całego ruchu ICMP', 'correct': true },
    ],
  },
  {
    'text': '286. Mechanizm User Account Control (UAC) systemu Windows:',
    'answers': [
      {
        'text':
          'blokuje konto po zdefiniowanej wcześniej ilości nieudanych prób logowania',
        'correct': false,
      },
      {
        'text':
          'wprowadza dodatkową formę ochrony konta administracyjnego m.in. przed koniami trojańskimi i złośliwym oprogramowaniem',
        'correct': true,
      },
      {
        'text':
          'pozwala administratorowi chwilowo skorzystać z pełnego tokenu administracyjnego',
        'correct': true,
      },
      {
        'text':
          'wirtualizuje dostęp do newralgicznych komponentów systemu plików',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '287. Klucz szyfrowania, którym zaszyfrowana została treść pliku (standardowym mechanizmem EFS z systemu NTFS):',
    'answers': [
      {
        'text': 'znajduje się w certyfikacie właściciela pliku',
        'correct': false,
      },
      {
        'text':
          'znajduje się w certyfikacie każdego agenta DRA w systemie operacyjnym',
        'correct': false,
      },
      {
        'text': 'jest zapisany wewnątrz zaszyfrowanego pliku',
        'correct': true,
      },
      {
        'text':
          'znajduje się w certyfikacie administratora systemu operacyjnego',
        'correct': false,
      },
      {
        'text': 'jest przechowywany wraz z zaszyfrowanym plikiem',
        'correct': true,
      },
    ],
  },
  {
    'text': '290. Przy kopiowaniu zaszyfrowanego pliku z NTFS na partycję FAT:',
    'answers': [
      {
        'text':
          'plik będzie możliwy do odczytu tylko na systemie, na którym został zaszyfrowany',
        'correct': false,
      },
      { 'text': 'plik zostaje odszyfrowany', 'correct': true },
      {
        'text': 'plik będzie później wymagał ręcznego odszyfrowania',
        'correct': false,
      },
      {
        'text':
          'plik może być skopiowany tylko przez użytkownika "Data Recovery Agent"',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '291. Zaznacz poprawne warunki, których spełnienie w systemie plików NTFS pozwoli by użytkownik U należący do grupy G mógł odczytać zawartość pliku P w katalogu K:',
    'answers': [
      {
        'text': 'U lub G dziedziczą dostęp do odczytu z katalogu K',
        'correct': true,
      },
      {
        'text':
          'U jawnie odebrano prawo odczytu P, ale U dziedziczy to prawo z katalogu K',
        'correct': false,
      },
      {
        'text':
          'U jawnie odebrano prawo odczytu P, ale G dziedziczy to prawo z katalogu K',
        'correct': false,
      },
      {
        'text': 'U lub G mają jawnie nadane prawo odczytu pliku P',
        'correct': true,
      },
      {
        'text':
          'tylko U ma jawnie nadany dostęp do P i K, G nie nadano żadnych praw ani do K, ani do P',
        'correct': true,
      },
      {
        'text':
          'tylko U dziedziczy dostęp do P i K, G nie dziedziczy żadnych praw ani do K, ani do P',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '292. Wskaż to z ustawień parametrów haseł (tylko jedno), które jest najkorzystniejsze dla bezpieczeństwa konta:',
    'answers': [
      { 'text': 'okres ważności hasła: nieskończony', 'correct': false },
      { 'text': 'maksymalna długość: 14 znaków', 'correct': false },
      { 'text': 'minimalna długość: 10 znaków', 'correct': true },
      { 'text': 'odwracalne szyfrowanie haseł: włączone', 'correct': false },
    ],
  },
  {
    'text': '293. getfacl --omit-header test ... Oznacza, że:',
    'answers': [
      {
        'text': 'grupa "agents" może modyfikować zawartość obiektu test',
        'correct': false,
      },
      {
        'text': 'właściciel może tworzyć pliki w katalogu test',
        'correct': true,
      },
      {
        'text': 'użytkownik "jbond" może modyfikować zawartość obiektu test',
        'correct': false,
      },
      {
        'text':
          'użytkownik "jbond" może przeglądać listę plików w katalogu test',
        'correct': true,
      },
    ],
  },
  {
    'text': '294. Stosowany w sieciach VPN preshared key to:',
    'answers': [
      {
        'text':
          'klucz publiczny z predefiniowanego certyfikatu SSL służący do generacji asymetrycznego klucza szyfrowania danych',
        'correct': false,
      },
      {
        'text':
          'statycznie ustalony po obu stronach tunelu klucz symetryczny lub hasło',
        'correct': true,
      },
      {
        'text':
          'mechanizm uwierzytelniania wykorzystujący generowane losowo po obu stronach wstępne klucze asymetryczne D-H',
        'correct': false,
      },
      {
        'text': 'mechanizm pozwalający uwierzytelniać strony tunelu',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '296. Asocjacja bezpieczeństwa (ang. Security Association) IPsec w systemie Windows:',
    'answers': [
      {
        'text':
          'to protokół zestawiania tunelu IPsec, w którym negocjowane są parametry tunelu',
        'correct': false,
      },
      {
        'text': 'może być monitorowana przez systemową zaporę sieciową',
        'correct': true,
      },
      {
        'text':
          'obejmuje zestaw parametrów niezbędnych do komunikacji w tunelu IPsec',
        'correct': true,
      },
      {
        'text':
          'to polityka IPsec określająca filtry pakietów poddawanych tunelowaniu',
        'correct': false,
      },
    ],
  },
  {
    'text': '302. Historia haseł jest przechowywana przez system operacyjny:',
    'answers': [
      {
        'text': 'aby wykluczyć ponowne użycie tego samego hasła jednorazowego',
        'correct': false,
      },
      {
        'text':
          'aby wykluczyć ustawienie nowego hasła identycznego z jakimkolwiek wcześniej wybranych przez tego samego użytkownika od początku',
        'correct': false,
      },
      {
        'text':
          'w połączeniu z minimalnym okresem ważności hasła, aby wykluczyć zbyt częste wybieranie przez użytkownika tego samego nowego hasła',
        'correct': true,
      },
      {
        'text':
          'aby umożliwić tzw. przypomnienie haseł użytkowników (szczególnie użyteczne w przypadku aplikacji nieobsługujących funkcji jednokierunkowych)',
        'correct': false,
      },
    ],
  },
  {
    'text': '303. Pojedyncza reguła zapory sieciowej Windows:',
    'answers': [
      {
        'text':
          'może dotyczyć jednocześnie ruchu przychodzącego i wychodzącego',
        'correct': false,
      },
      {
        'text': 'może dotyczyć wszystkich 3 profili sieciowych jednocześnie',
        'correct': true,
      },
      {
        'text': 'może być ustawiona z użyciem polecenia netsh',
        'correct': true,
      },
      { 'text': 'może dotyczyć tylko wskazanego programu', 'correct': true },
    ],
  },
  {
    'text':
      '304. Grupa użytkowników w systemie MS Windows o nazwie Użytkownicy uwierzytelnieni:',
    'answers': [
      { 'text': 'jest identyczna z grupą Wszyscy', 'correct': false },
      { 'text': 'jest podzbiorem grupy Wszyscy', 'correct': true },
      {
        'text': 'obejmuje wszystkich użytkowników lokalnych',
        'correct': false,
      },
      { 'text': 'nie obejmuje konta Gość', 'correct': true },
    ],
  },
  {
    'text': '305. Mechanizm mandatory Integrity Control (MIC) system Windows:',
    'answers': [
      {
        'text':
          'przypisuje procesowi jeden z 5 poziomów uprawnień uwzględnianych dodatkowo w kontroli dostępu',
        'correct': true,
      },
      {
        'text': 'pozwala ograniczyć dostęp do odczytu dla wybranych plików',
        'correct': false,
      },
      {
        'text': 'pozwala ograniczyć dostęp do zapisu w systemie plików',
        'correct': true,
      },
      {
        'text': 'pozwala ograniczyć swobodę komunikacji między procesami',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '306. Wskaż pliki zaangażowane w konfigurację TCP wrappera w systemie Unix:',
    'answers': [
      { 'text': '/etc/hosts.allow', 'correct': true },
      { 'text': '/etc/hosts', 'correct': false },
      { 'text': '/etc/hosts.deny', 'correct': true },
      { 'text': '/etc/hosts.equiv', 'correct': false },
    ],
  },
  {
    'text': '307. Wybierz prawdziwą kolejność operacji NAT:',
    'answers': [
      {
        'text':
          'PREROUTING(mangle) PREROUTING(nat) FILTERING POSTROUTING(nat) POSTROUTING(mangle)',
        'correct': false,
      },
      {
        'text':
          'PREROUTING(nat) PREROUTING(mangle) FILTERING POSTROUTING(nat) POSTROUTING(mangle)',
        'correct': false,
      },
      {
        'text':
          'PREROUTING(nat) PREROUTING(mangle) FILTERING POSTROUTING(mangle) POSTROUTING(nat)',
        'correct': false,
      },
      {
        'text':
          'PREROUTING(mangle) PREROUTING(nat) FILTERING POSTROUTING(mangle) POSTROUTING(nat)',
        'correct': true,
      },
    ],
  },
  {
    'text': '309. Które konfiguracje tuneli obsługuje system OpenVPN:',
    'answers': [
      {
        'text': '1 do wielu przy uwierzytelnianiu poprzez wspólny klucz',
        'correct': false,
      },
      {
        'text': '1 do 1 przy uwierzytelnianiu poprzez certyfikaty X.509',
        'correct': true,
      },
      {
        'text': '1 do 1 przy uwierzytelnianiu poprzez wspólny klucz',
        'correct': true,
      },
      {
        'text': '1 do wielu przy uwierzytelnianiu poprzez certyfikaty X.509',
        'correct': true,
      },
    ],
  },
  {
    'text': '313. Udział C$ jest to:',
    'answers': [
      {
        'text':
          'udział domyślny kontrolera domeny służący do obsługi logowania w sieci',
        'correct': false,
      },
      {
        'text':
          'udział służący do dostępu do dysku C w celach zdalnej administracji',
        'correct': true,
      },
      {
        'text': 'udział komunikacji międzyprocesowej w systemie operacyjnym',
        'correct': false,
      },
      { 'text': 'udział do komunikacji IPsec', 'correct': false },
    ],
  },
  {
    'text':
      '314. Jaka jest kolejność sprawdzania reguł w plikach hosts.deny hosts.allow:',
    'answers': [
      {
        'text':
          'jeśli znajdzie się najpierw dopasowanie w deny to allow w ogóle nie jest sprawdzane',
        'correct': false,
      },
      { 'text': 'najpierw deny do pierwszego dopasowania', 'correct': false },
      { 'text': 'najpierw allow do pierwszego dopasowania', 'correct': true },
      {
        'text':
          'jeśli znajdzie się najpierw dopasowanie w allow to deny w ogóle nie jest sprawdzane',
        'correct': true,
      },
    ],
  },
  {
    'text': '315. Co można ustawić w zasadach kont w MS Windows:',
    'answers': [
      { 'text': 'minimalną długość nazwy użytkownika', 'correct': false },
      { 'text': 'maksymalną długość nazwy użytkownika', 'correct': false },
      { 'text': 'minimalną długość hasła', 'correct': true },
      { 'text': 'maksymalną długość hasła', 'correct': false },
      { 'text': 'złożoność hasła', 'correct': true },
      { 'text': 'szyfrowanie AES', 'correct': false },
      { 'text': 'Minimalny czas ważności hasła', 'correct': true },
    ],
  },
  {
    'text':
      '316. Czy maska uprawnień POSIX ACL jest definiowana dla każdego użytkownika osobno?',
    'answers': [
      {
        'text': 'tak, z priorytetem maski domyślnej (logiczny AND)',
        'correct': false,
      },
      {
        'text': 'nie, maskę można zdefiniować tylko dla grup użytkowników',
        'correct': false,
      },
      {
        'text': 'tak, jeśli jawnie wskażemy nazwę użytkownika',
        'correct': false,
      },
      {
        'text': 'nie, istnieje tylko jedna obowiązująca maska',
        'correct': true,
      },
    ],
  },
  {
    'text': '318. Szyfrowanie symetryczne plików mechanizmem EFS systemu NTFS:',
    'answers': [
      {
        'text':
          'może być realizowane po zainstalowaniu dodatkowego oprogramowania DRA',
        'correct': false,
      },
      {
        'text':
          'może być realizowane pod warunkiem posiadania przez użytkownika certyfikatu klucza publicznego',
        'correct': true,
      },
      {
        'text': 'szyfruje pliki użytkownika jego kluczem prywatnym',
        'correct': false,
      },
      {
        'text':
          'nie jest realizowane przez system operacyjny starszy niż Windows 10',
        'correct': false,
      },
    ],
  },
  {
    'text': '319. Mechanizm impersonation systemu Windows:',
    'answers': [
      {
        'text': 'jest wykorzystywany przez polecenie <code>runas</code>',
        'correct': true,
      },
      {
        'text':
          'pozwala zdefiniować dla użytkownika inną nazwę wyświetlaną (np. imię i nazwisko) niż nazwę konta',
        'correct': false,
      },
      {
        'text':
          'definiuje 5 dodatkowych poziomów kontroli dostępu do danych i procesów',
        'correct': false,
      },
      {
        'text':
          'pozwala procesowi użyć chwilowo innego niż bieżący tokenu zabezpieczeń',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '324. Kiedy w Windowsie następuje zerowanie licznika prób wpisania hasła:',
    'answers': [
      { 'text': 'Po pomyślnym zalogowaniu', 'correct': true },
      { 'text': 'Po upływie określonego czasu', 'correct': true },
      { 'text': 'Administrator może ręcznie wyzerować', 'correct': true },
      {
        'text': 'nie pamiętam, ale nie powinno być zaznaczone',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '325. Czy iptables umożliwia określenie domyślnej polityki w łańcuchu?',
    'answers': [
      { 'text': 'Tylko w łańcuchach tablicy filter', 'correct': false },
      { 'text': 'Tylko w predefiniowanych łańcuchach', 'correct': true },
      { 'text': 'Tak, w każdym łańcuchu', 'correct': false },
      { 'text': 'tylko w nowo utworzonych lancuchach', 'correct': false },
      { 'text': 'tak', 'correct': false },
      { 'text': 'tylko w standardowych lancuchach', 'correct': true },
      { 'text': 'Nie', 'correct': false },
    ],
  },
  {
    'text':
      '328. Czy certyfikaty SSL dla obu stron polaczenia vpn nawiazanego przy pomocy programu OpenVPN musza by podpisane przez ta sam zaufana strone trzecia?',
    'answers': [
      {
        'text': 'nie, poniewaz nie ma takiej opcji w OpenVPN',
        'correct': false,
      },
      {
        'text':
          'nie, poniewaz nie ma znaczenia czy to jest to samo CA, wazne aby zaufanie strony trzeciej bylo ogolnie znane CA, np. Thawte, VeriSign, Unizeto',
        'correct': false,
      },
      {
        'text':
          'nie trzeba podawac parametru wskazujacego na CA, jest to opcjonalne',
        'correct': false,
      },
      { 'text': 'tak', 'correct': true },
    ],
  },
  {
    'text':
      '330. Wskaz prawidlowe stwierdzenia dotyczace metod uwierzytelniania systemow operacyjnych MS Windows w srodowisku sieciowym:',
    'answers': [
      {
        'text': 'Kerberos jest bezpieczniejszy niz LM i NTLM',
        'correct': true,
      },
      { 'text': 'LM jest bezpieczniejszy niz NTLM', 'correct': false },
      {
        'text':
          'Kerberos jest bezpieczniejszy niz NTLM, ale jest dostepny tylko w srodowisku domenowym',
        'correct': true,
      },
      { 'text': 'NTLM jest bezpieczniejszy niz LM', 'correct': true },
    ],
  },
  {
    'text': '334. Zapora sieciowa wbudowana w Ms Win XP sp2:',
    'answers': [
      { 'text': 'jest typu stateless', 'correct': false },
      {
        'text':
          'jest jedyna mozliwa do zastosowania zapora sieciowa w systemie',
        'correct': false,
      },
      {
        'text': 'pozwala powiadamiac uzytkownika droga mailowa o zagrozeniach',
        'correct': false,
      },
      { 'text': 'jest zapora typu stateful', 'correct': true },
    ],
  },
  {
    'text':
      '335. W jaki sposob mozna utworzyc wiele polaczen z danego hosta za pomoca programu OpenVPN?',
    'answers': [
      {
        'text':
          'nalezy powtorzyc wpisanie opcji: remote tyle razy ile polaczen VPN mamy utworzyc',
        'correct': false,
      },
      {
        'text':
          'nalezy uruchomic program OpenVPN z przelacznikiem: --force-multi-instance',
        'correct': false,
      },
      { 'text': 'nie ma takiej mozliwosci', 'correct': false },
      {
        'text':
          'nalezy uruchomic program OpenVPN z wieloma plikami konfiguracyjnymi, kazdy plik definiuje jedno polaczenie',
        'correct': true,
      },
      {
        'text':
          'nalezy wykorzystac opcje --mode server ale tylko dla polaczen z zastosowaniem certyfikatow SSL',
        'correct': false,
      },
      {
        'text':
          'nalezy uruchomic kolejne instancje programu OpenVPN wraz z osobnymi plikami konfiguracyjnymi',
        'correct': true,
      },
    ],
  },
  {
    'text': '336. Ktore polecenie bedzie poprawne, dla ustalenia DNAT?',
    'answers': [
      {
        'text':
          'iptables -t nat -A FORWARD -d 150.254.17.3 -i eth- -j DNAT --to 192.168.1.1',
        'correct': false,
      },
      {
        'text':
          'iptables -t nat -A PREROUTING -d 150.254.17.3 -i eth0 -j NAT --to 192.168.1.1',
        'correct': false,
      },
      {
        'text':
          'iptables -t nat -A PREROUTING -i eth0 -j SAME --to 150.254.17.2',
        'correct': false,
      },
      {
        'text':
          'iptables -t nat -A PREROUTING -d 150.254.17.3 -i eth0 -j DNAT --to 192.168.1.1',
        'correct': true,
      },
      {
        'text':
          'iptables -t nat -A POSTROUTING -d 150.254.17.3 -i eth0 -j DNAT --to 192.168.1.1',
        'correct': false,
      },
      {
        'text':
          'iptables -t nat -A POSTROUTING -o eth0 -j SAME --to 150.254.17.2',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '337. Ponizsza regula zostala wpisana na komputerze pelniacym role routera: iptables -t filter -A INPUT -m state --state NEW -j DROP',
    'answers': [
      { 'text': 'odrzuca nowe polaczenia do tego komputera', 'correct': true },
      {
        'text': 'odrzuca nowe polaczenia inicjalizowane przez ten komputer',
        'correct': false,
      },
      {
        'text': 'odrzuca nowe polaczenia przechodzace przez ten komputer',
        'correct': false,
      },
      {
        'text': 'DROP znaczy nie przeszukuj dalej zapory, przepusc pakiet',
        'correct': false,
      },
    ],
  },
  {
    'text': '338. Narzedzie OpenVPN:',
    'answers': [
      { 'text': 'dziala tylko na protokole TCP', 'correct': false },
      {
        'text':
          'wykorzystuje mechanizm pre-shared key do losowego generowania kluczy',
        'correct': false,
      },
      {
        'text': 'nie ma wyroznionego programu serwerowego i klienckiego',
        'correct': true,
      },
      { 'text': 'jest przykladem SSL-VPN', 'correct': true },
      {
        'text':
          'wykorzystuje certyfikaty MD5 i funkcje skrotu SHA-1 do uwierzytelniania stron i szyfrowania ruchu sieciowego',
        'correct': false,
      },
      {
        'text':
          'wykorzystuje mechanizm SSL-VPN do laczenia sie z serwerami wspierajacymi protokol https np. Apache',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '343. Czy polecenie jest poprawne? iptables -t mangle -A PREROUTING -s localnet -d ! localnet -m ipp2p --dc -m comment --comment "zla regulka" -j TTL --ttl-set 1',
    'answers': [
      { 'text': 'tak, ale system bedzie usuwal te pakiety', 'correct': true },
      {
        'text':
          'tak, lecz taka regula niczego nie zmieni, gdyz nie ma celu ACCEPT lub DROP',
        'correct': false,
      },
      {
        'text': 'nie, gdyz nie mozna uzywac wielu argumentow " -m"',
        'correct': false,
      },
      {
        'text':
          'nie, gdyz cel TTL moze byc uzywany tylko w lancuchu POSTROUTING',
        'correct': false,
      },
    ],
  },
  {
    'text': '344. Idea polaczen typu VPN jest:',
    'answers': [
      {
        'text':
          'zmiana routingu pakietow, aby z jednej sieci pakiety trafialy bezposrednio do sieci docelowej',
        'correct': false,
      },
      {
        'text':
          'wsparcie polaczen p2p, aby hosty mogly bezposrednio komunikowal sie',
        'correct': false,
      },
      {
        'text':
          'obejscie problemow z polaczeniami z sieciami zlokalizowanymi za NAT',
        'correct': false,
      },
      {
        'text':
          'mozliwosc zapewnienia bardziej niezawodnych, w sensie polaczeniowym, niz TCP polaczen miedzy hostami',
        'correct': false,
      },
      {
        'text': 'utworzenie sieci laczacej odseparowane, odlegle sieci lokalne',
        'correct': true,
      },
    ],
  },
  {
    'text': '345. Opcja PARANOID w pliku hosts.deny:',
    'answers': [
      {
        'text':
          'blokuje zdalne zarzadzanie mechanizmem TCP wrappers, pozostawiajac dostep tylko z lokalnego hosta',
        'correct': false,
      },
      {
        'text':
          'wymusza sprawdzanie segmentow TCP czy sa poprawne w stosunku do norm RFC',
        'correct': false,
      },
      {
        'text':
          'pozwala ograniczyc ilosc pakietow/s przychodzacych do danej uslugi',
        'correct': false,
      },
      {
        'text':
          'blokuje pakiety pochodzace od hosta, ktorego ip nie posiada nazwy domenowej',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '346. getfacl --omit-header acl-test5 user::r-x user:inf44444:r-- group::rw- group:student:r-x mask::rwx other::--x Oznacza:',
    'answers': [
      {
        'text': 'uzytkownik "inf44444" nie moze czytac pliku acl-test5',
        'correct': false,
      },
      {
        'text': 'wlasciciel ma prawo zmodyfikowac zawartosc katalogu acl-test5',
        'correct': false,
      },
      {
        'text': 'uzytkownik "inf44444" moze czytac plik acl-test5',
        'correct': true,
      },
      {
        'text': 'maska blokuje wszystkie uprawnienia do pliku acl-test5',
        'correct': false,
      },
      {
        'text': 'grupa wlasciciela moze zmodyfikowac plik acl-test5',
        'correct': true,
      },
      {
        'text': 'grupa "student" moze zmodyfikowac plik acl-test5',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '349. getfacl --omit-header acl-test1 user::rw- user:junior:rwx group::r-- group:student:r-x mask::r-- other::--- Oznacza, ze:',
    'answers': [
      { 'text': 'wlasciciel moze wykonac plik', 'correct': false },
      {
        'text': 'grupa domyslna/wlasciciela moze odczytac plik',
        'correct': true,
      },
      { 'text': 'uzytkownik "junior" moze wykonac plik', 'correct': false },
      { 'text': 'wlasciciel moze modyfikowac plik', 'correct': true },
      { 'text': 'grupa "student" moze wykonac plik', 'correct': false },
      { 'text': 'inni moga zmodyfikowac plik', 'correct': false },
    ],
  },
  {
    'text':
      '350. Jak zachowa sie system kontroli ACL standardu POSIX w przypadku uzytkownika U nalezacego do grupy G i wpisanego na liscie ACL obiektu p, jesli ani U ani G nie maja jawnie przydzielonego prawa r, ale kategoria "wszyscy uzytkownicy" (others) takie uprawnienie do obiektu posiada:',
    'answers': [
      {
        'text':
          'prawo r do obiektu p zostanie efektywnie przyznane, o ile U jest wlascicielem p',
        'correct': false,
      },
      {
        'text':
          'prawo r do obiektu p zostanie efektywnie przyznane bezwarunkowo',
        'correct': false,
      },
      {
        'text': 'prawo r do obiektu p nie zostanie efektywnie przyznane',
        'correct': true,
      },
      {
        'text':
          'prawo r do obiektu p nie zostanie efektywnie przyznane, ale U odziedziczy je w glab, jesli p jest katalogiem',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '355. Czy istnieje mozliwosc zmiany portu docelowego i adresu docelowego na adres localhost i dowolny inny port?',
    'answers': [
      { 'text': 'tak', 'correct': false },
      {
        'text': 'tylko, jesli okreslimy protokol oraz oryginalny port docelowy',
        'correct': true,
      },
      { 'text': 'tylko poprzez dodatkowy modul', 'correct': false },
      { 'text': 'nie', 'correct': false },
    ],
  },
  {
    'text':
      '356. W jaki sposob program OpenVPN bedzie wiedzial, gdzie znajduje sie drugi koniec tunelu VPN:',
    'answers': [
      {
        'text':
          'OpenVPN w sposob interaktywny poprosi uzytkownika o podanie adresu IP i numeru portu',
        'correct': false,
      },
      {
        'text': 'nalezy wpisac odpowiednia opcje w pliku konfiguracyjnym',
        'correct': true,
      },
      {
        'text': 'OpenVPN wysle zapytanie do najblizszego serwera VPN',
        'correct': false,
      },
      {
        'text':
          'OpenVPN odczytuje zawartosc zdalnej tablicy routingu i pobiera ta informacje',
        'correct': false,
      },
    ],
  },
  {
    'text': '357. Dyrektywa "mask" w ACL okresla:',
    'answers': [
      { 'text': 'mozna ja modyfikowac jedynie raz', 'correct': false },
      { 'text': 'jest utozsamiana z uprawnieniami grupy', 'correct': true },
      {
        'text': 'ukrywanie nadanych uprawnien dodatkowych uzytkownikow',
        'correct': false,
      },
      { 'text': 'nie ma zadnego znaczenia', 'correct': false },
    ],
  },
  {
    'text': '358. Opcja spawn w pliku hosts.deny:',
    'answers': [
      {
        'text': 'pozwala tworzyc kolejne procesy TCP wrapper',
        'correct': false,
      },
      {
        'text': 'jest wykorzystywana tylko w pliku hosts.allow',
        'correct': false,
      },
      { 'text': 'nie jest wykorzystywana', 'correct': false },
      {
        'text':
          'pozwala odeslac do nadawcy specjalnie spreparowana wiadomosc w odpowiedzi na zadanie',
        'correct': true,
      },
    ],
  },
  {
    'text': '359. Ktore polecenie bedzie poprawne, dla ustalenia SNAT:',
    'answers': [
      {
        'text': 'iptables -t nat -A FORWARD -o eth0 -j SNAT --to 150.254.17.2',
        'correct': false,
      },
      {
        'text':
          'iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 150.254.17.2',
        'correct': true,
      },
      {
        'text':
          'iptables -t nat -A PREROUTING -o eth0 -j SAME --to 150.254.17.2',
        'correct': false,
      },
      {
        'text':
          'iptables -t nat -A POSTROUTING -o eth0 -j NAT --to 150.254.17.2',
        'correct': false,
      },
      {
        'text':
          'iptables -t fnat -A PREROUTING -o eth0 -j SNAT --to 150.254.17.2',
        'correct': false,
      },
      {
        'text':
          'iptables -t nat -A POSTROUTING -o eth0 -j SAME --to 150.254.17.2',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '360. Czy iptables umozliwia ograniczenie dostepu do uslugi w jednym poleceniu?',
    'answers': [
      { 'text': 'jesli okreslamy protokol', 'correct': false },
      { 'text': 'jesli nie okreslimy protokolu', 'correct': false },
      { 'text': 'nie', 'correct': false },
      { 'text': 'tak', 'correct': true },
    ],
  },
  {
    'text':
      '361. Oprogramowanie OpenVPN wykorzystuje tablice routingu w Linuxie:',
    'answers': [
      {
        'text':
          'do sprawdzenia kosztu trasy prowadzacej do sieci po drugiej stronie polaczenia VPN',
        'correct': false,
      },
      {
        'text':
          'aby dowiedziec sie jak nawiazac polaczenie z siecia po drugiej stronie tunelu VPN',
        'correct': false,
      },
      {
        'text':
          'do przechowywania trasy do sieci dostepnej po drugiej stronie polaczenia VPN',
        'correct': true,
      },
      {
        'text':
          'jako bufor przechowujacy nadchodzace informacje o zmianie trasy do odleglej sieci po drugiej stronie polaczenia VPN',
        'correct': false,
      },
    ],
  },
  {
    'text': '362. Nazwa konta "administrator" w systemie Ms Windows XP:',
    'answers': [
      { 'text': 'mozna ja zmienic w kazdej chwili', 'correct': true },
      { 'text': 'jest definiowana przy instalacji systemu', 'correct': false },
      {
        'text':
          'mozna ja zmienic tylko przy wykorzystaniu dodatkowego oprogramowania',
        'correct': false,
      },
      { 'text': 'jest stala i nie moze byc zmieniona', 'correct': false },
    ],
  },
  {
    'text':
      '365. user::rw- user:inf44444:r-x group::rwx group:student:rwx mask::rwx other::--- Oznacza:',
    'answers': [
      { 'text': 'grupa "student" nie moze skasowac pliku', 'correct': false },
      { 'text': 'uzytkownik "inf44444" moze wykonac plik', 'correct': true },
      { 'text': 'grupa "student" moze skasowac katalog', 'correct': true },
      { 'text': 'wlasciciel moze wykonac plik', 'correct': false },
      { 'text': 'maska blokuje wszystkie uprawnienia', 'correct': false },
      {
        'text': 'grupa domyslna (wlasciciela) nie moze zmodyfikowac pliku',
        'correct': false,
      },
    ],
  },
  {
    'text': '366. Czy system MS Windows korzysta z serwera Kerberos?',
    'answers': [
      { 'text': 'nigdy', 'correct': false },
      { 'text': 'tylko w starszych systemach (95, 98)', 'correct': false },
      { 'text': 'zawsze', 'correct': false },
      { 'text': 'jesli zostanie odpowiednio skonfigurowany', 'correct': true },
    ],
  },
  {
    'text': '371. Pre-shared key to:',
    'answers': [
      {
        'text':
          'przestarzaly mechanizm sluzacy do logowania sie na zdalnego hosta bez podawania hasla',
        'correct': false,
      },
      { 'text': 'cos takiego nie istnieje', 'correct': false },
      {
        'text':
          'prosty mechanizm pozwalajacy szyfrowac i uwierzytelniac strony za pomoca jednego klucza',
        'correct': true,
      },
      {
        'text':
          'silny mechanizm uwierzytelniania wykorzystujacy generowany losowo po obu stronach klucz',
        'correct': false,
      },
      {
        'text':
          'silny mechanizm szyfrowania wykorzystujacy certyfikaty SSL do generacji losowego klucza sesyjnego',
        'correct': false,
      },
      { 'text': 'jest to przyklad kryptografii symetrycznej', 'correct': true },
    ],
  },
  {
    'text': '376. Czy TCP wrapper to:',
    'answers': [
      {
        'text': 'samodzielny program analizujacy tylko polaczenia tcp',
        'correct': false,
      },
      {
        'text':
          'lata (ang. patch) rozszerzajaca funkcjonalnosc programu xinetd',
        'correct': false,
      },
      {
        'text':
          'program analizujacy tylko przychodzace polaczenia tcp, ale dla numerow portow na ktorych uruchomione sa uslugi zarzadzane przez xinetd',
        'correct': true,
      },
      {
        'text':
          'program w postaci prostego firewalla za pomoca ktorego mozna blokowac wychodzace polaczenia, odpowiednie reguly zapisywane sa w plikach /etc/hosts.allow i /etc/hosts.deny',
        'correct': false,
      },
      {
        'text':
          'dodatkowy podsystem sieciowy dla systemu operacyjnego Linux pozwalajacy na nakladanie ograniczen dla polaczen przychodzacych',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '377. user::r-x user:inf44444:r-- group::rw- group:student:r-x mask::rwx other::--x Oznacza:',
    'answers': [
      { 'text': 'wszyscy moga wykonac plik', 'correct': true },
      { 'text': 'grupa "student" moze zmodyfikowac plik', 'correct': false },
      {
        'text': 'uzytkownik "inf44444" nie moze czytac plik',
        'correct': false,
      },
      { 'text': 'uzytkownik "inf44444" moze czytac plik', 'correct': true },
      { 'text': 'grupa wlasciciela moze zmodyfikowac plik', 'correct': true },
      { 'text': 'maska blokuje wszystkie uprawnienia', 'correct': false },
    ],
  },
  {
    'text':
      '378. Jaka usluga jest szczegolnie trudna do filtrowania statycznego?',
    'answers': [
      {
        'text': 'ftp, poniewaz domyslnie serwery dzialaja w trybie pasywnym',
        'correct': false,
      },
      {
        'text': 'ftp, poniewaz domyslnie serwery dzialaja w trybie aktywnym',
        'correct': true,
      },
      { 'text': 'rlogin, bo costam', 'correct': false },
      { 'text': 'rlogin, bo drugie costam', 'correct': false },
    ],
  },
  {
    'text': '379. Certyfikat EFS używany w NTFS zawiera:',
    'answers': [
      { 'text': 'klucz, którym szyfruje się pliki', 'correct': false },
      { 'text': 'klucz, którym deszyfruje się pliki', 'correct': false },
      {
        'text':
          'klucz publiczny użytkownika, używany do odszyfrowywania kluczy FEK',
        'correct': true,
      },
      {
        'text':
          'klucz publiczny użytkownika, używany do szyfrowania kluczy FEK',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '380. Które stwierdzenia dotyczące blokady konta użytkownika w systemie Windows są nieprawdziwe:',
    'answers': [
      {
        'text':
          'licznik prób logowania jest zerowany po każdym nieudanym logowaniu',
        'correct': true,
      },
      {
        'text':
          'licznik prób logowania jest zerowany automatycznie po zadanym czasie',
        'correct': false,
      },
      {
        'text': 'licznik prób logowania może wyzerować administrator',
        'correct': false,
      },
      {
        'text':
          'licznik prób logowania jest zerowany po każdym pomyślnym zalogowaniu',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '381. Zasoby systemu operacyjnego MS Windows udostępnione poprzez SMB:',
    'answers': [
      {
        'text':
          'są dostępne zdalnie tylko dla tych użytkowników, którzy posiadają lokalne konto w systemie operacyjnym',
        'correct': false,
      },
      { 'text': 'nazywa się portami', 'correct': false },
      {
        'text':
          'zawsze wymagają uwierzytelniania (podania hasła) przy dostępie zdalnym',
        'correct': false,
      },
      {
        'text':
          'mogą mieć ograniczony dostęp do odczytu i/lub zapisu tylko dla wskazanych użytkowników',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '382. Użytkownik U systemu Linux należący do grupy G1 nie ma wpisu na liście ACL do zasobu O w systemie plików. Jednak grupie G1 na liście ACL zasobu O nadano prawa r i x, a uprawnienia domyślne tego zasobu wynoszą rwx. Jakie efektywne uprawnienia do O posiada U? (U nie jest właścicielem O i nie należy do grupy zasobu O, mask=rwx)',
    'answers': [
      { 'text': 'tylko r', 'correct': false },
      { 'text': 'rx', 'correct': true },
      { 'text': 'rwx', 'correct': false },
      { 'text': 'żadne', 'correct': false },
    ],
  },
  {
    'text':
      '385. Mechanizm wirtualizacji dostępu do newralgicznych komponentów systemu Windows:',
    'answers': [
      {
        'text': 'dotyczy niektórych obiektów rejestru systemowego',
        'correct': true,
      },
      {
        'text':
          'może być włączany/wyłączany przez użytkownika dla jego własnych procesów',
        'correct': false,
      },
      { 'text': 'dotyczy niektórych obiektów systemu plików', 'correct': true },
      {
        'text': 'jest stosowany wyłącznie wobec aplikacji 64-bitowych',
        'correct': false,
      },
    ],
  },
  {
    'text': '386. Których wpisów ACE na liście POSIX ACL dotyczy maska:',
    'answers': [
      { 'text': 'właściciela obiektu', 'correct': false },
      { 'text': 'grupy (domyślnej) pliku (z bazowych ACE)', 'correct': true },
      { 'text': 'każdej jawnie wpisanej grupy', 'correct': true },
      {
        'text':
          'wszystkich użytkowników niewpisanych jawnie, ale należących do dowolnej jawnie wpisanej grupy',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '388. $ getfacl skrypt user::rw- user:jbond:r-x group::rwx group:agents:rwx mask::r-x other::- Oznacza, że:',
    'answers': [
      { 'text': 'grupa agents może zmodyfikować skrypt', 'correct': false },
      {
        'text': 'grupa domyślna (owning group) może zmodyfikować skrypt',
        'correct': false,
      },
      { 'text': 'użytkownik jbond może wykonać skrypt', 'correct': true },
      {
        'text': 'pozostali użytkownicy mogą zmodyfikować skrypt',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '389. TCP Wrapper może korzystać z dwóch plików z regułami polityki, przy czym:',
    'answers': [
      {
        'text':
          'ponieważ stosuje zasadę pierwszego dopasowania, plik /etc/hosts.deny może nie być w ogóle sprawdzany',
        'correct': true,
      },
      {
        'text':
          'jeśli reguła nie zostaje odnaleziona w żadnym pliku, to dostęp zostaje odrzucony',
        'correct': false,
      },
      {
        'text':
          'najpierw sprawdzane są reguły z pliku /etc/hosts.deny, a ewentualnie później reguły z pliku /etc/hosts.allow',
        'correct': false,
      },
      {
        'text':
          'najpierw sprawdzane są reguły z pliku /etc/hosts.allow, a ewentualnie później reguły z pliku /etc/hosts.deny',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '390. Które stwierdzenia najlepiej opisują mechanizm Bypass Traverse Checking:',
    'answers': [
      {
        'text':
          'pozwala na wyświetlanie zawartości katalogu, do którego użytkownik nie ma przyznanego dostępu, ale ma dostęp do któregokolwiek pliku wewnątrz',
        'correct': false,
      },
      {
        'text':
          'pozwala na ominięcie sprawdzania uprawnień do katalogów na ścieżce do pliku, do którego użytkownik ma przyznany dostęp',
        'correct': true,
      },
      {
        'text':
          'pozwala na zestawianie tunelu IPsec w sieci wykorzystującej NAT (NAT-T)',
        'correct': false,
      },
      {
        'text':
          'pozwala na dostęp do udziałów sieciowych bez konieczności posiadania konta w zdalnym systemie',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '393. $getfacl test owner: jbond group: agents user::rw- user:jbond:r-x group:agents:--x mask::r-x other:--- W takim wypadku użytkownik jbond (będący właścicielem obiektu test), należący do grupy agents, ma efektywne uprawnienia:',
    'answers': [
      { 'text': 'rw', 'correct': true },
      { 'text': 'rx', 'correct': false },
      { 'text': 'r', 'correct': false },
      { 'text': 'rwx', 'correct': false },
    ],
  },
  {
    'text': '395. Windows Firewall pozwala tworzyć reguły:',
    'answers': [
      { 'text': 'przepuszczające wybrany ruch', 'correct': true },
      {
        'text': 'blokujące wysyłanie ruchu sieciowego przez wskazane programy',
        'correct': true,
      },
      {
        'text': 'blokujące odbieranie ruchu sieciowego przez wskazane programy',
        'correct': true,
      },
      { 'text': 'blokujące wybrany ruch', 'correct': true },
    ],
  },
  {
    'text':
      '397. Klucz z certyfikatu EFS użytkownika U jest wykorzystywany w systemie NTFS do:',
    'answers': [
      {
        'text':
          'szyfrowania jednorazowych kluczy, którymi zaszyfrowane zostały poszczególne pliki do których U ma dostęp',
        'correct': true,
      },
      {
        'text': 'szyfrowania i deszyfrowania treści plików należących do U',
        'correct': false,
      },
      {
        'text':
          'szyfrowania i deszyfrowania wszelkiej komunikacji z użytkownikiem U (np. poczty elektronicznej)',
        'correct': false,
      },
      {
        'text':
          'szyfrowania i deszyfrowania treści plików należących do użytkowników, którzy udostępnili te pliki użytkownikowi U',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '398. Użytkownik U systemu Linux jest właścicielem zasobu O w systemie plików i na liście ACL tego zasobu ma przyznane prawa rw, a maska zawiera prawa r oraz x. Jakie efektywne uprawnienia do O posiada aktualnie U?',
    'answers': [
      { 'text': 'tylko r', 'correct': false },
      { 'text': 'tylko w', 'correct': false },
      { 'text': 'rw', 'correct': true },
      { 'text': 'rwx', 'correct': false },
    ],
  },
  {
    'text': '399. Mechanizm mandatory Integrity Control (MIC) system Windows:',
    'answers': [
      {
        'text': 'pozwala ograniczyć swobodę komunikacji między procesami',
        'correct': true,
      },
      {
        'text': 'pozwala ograniczyć dostęp do zapisu w systemie plików',
        'correct': true,
      },
      {
        'text': 'pozwala ograniczyć dostęp do odczytu dla wybranych plików',
        'correct': false,
      },
      {
        'text':
          'przypisuje procesowi jeden z kilku poziomów uprawnień uwzględnianych dodatkowo w kontroli dostępu',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '400. Dany jest plik Tajne.txt w katalogu Jawne. Załóżmy, że użytkownik Adaś należy do grupy Users. Katalog Jawne ma przydzielone uprawnienia ACL dla grupy Users: ALLOW na czytanie i DENY na zapis. Plik Tajne.txt ma uprawnienia ALLOW na zapis dla użytkownika Adaś. Jakie uprawnienia ostatecznie ma Adaś do pliku Tajne.txt?',
    'answers': [
      {
        'text': 'ma uprawnienia do odczytu, brak uprawnień do zapisu',
        'correct': false,
      },
      { 'text': 'brak uprawnień do odczytu i zapisu', 'correct': false },
      { 'text': 'ma uprawnienia do odczytu i zapisu', 'correct': true },
      {
        'text': 'ma uprawnienia do zapisu, brak uprawnienia do odczytu',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '402. Czym różnią się klauzule DROP i REJECT w akcjach reguły iptables?',
    'answers': [
      {
        'text':
          'obie odrzucają pakiety, ale REJECT dotyczy tylko łańcucha FORWARD',
        'correct': false,
      },
      {
        'text': 'obie odrzucają pakiety, ale DROP zawsze robi to "po cichu"',
        'correct': true,
      },
      {
        'text':
          'obie odrzucają pakiety, ale DROP powoduje przerwanie przeglądania reguł, a REJECT nie',
        'correct': false,
      },
      {
        'text': 'REJECT odrzuca pakiety warunkowo, a DROP bezwarunkowo',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '404. Które zdania są prawdziwe w odniesieniu do aktywnego mechanizmu UAC w systemie Windows:',
    'answers': [
      {
        'text':
          'jeśli zwykły użytkownik chce wykonać operację wymagającą uprawnień administratora zostanie zapytany o hasło administratora',
        'correct': true,
      },
      {
        'text':
          'UAC blokuje możliwość instalacji programów przez administratora',
        'correct': false,
      },
      {
        'text':
          'zmiana istotnych gałęzi rejestru systemu wymaga świadomej reakcji uprawnionego użytkownika',
        'correct': true,
      },
      {
        'text':
          'UAC chroni przed przypadkowym uruchomieniem potencjalnie niebezpiecznych programów przez użytkownika',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '405. Które stwierdzenia dotyczące blokady konta w systemie Windows są prawdziwe:',
    'answers': [
      {
        'text':
          'licznik prób logowania jest zerowany po każdej udanej próbie logowania',
        'correct': true,
      },
      {
        'text':
          'w czasie określonym długością okresu zerowania licznika prób logowania, użytkownik nie może podjąć więcej udanych prób logowania niż określa próg blokady',
        'correct': false,
      },
      {
        'text':
          'istnieje ustawienie progu blokady dopuszczające nieblokowanie konta mimo dowolnej liczby niepomyślnych prób logowania',
        'correct': true,
      },
      {
        'text':
          'próg blokady określa ilość kolejnych niepomyślnych prób logowania, po osiągnięciu której dostęp do konta będzie zablokowany trwale (do odwołania przez administratora)',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '410. Wskaż prawdziwe stwierdzenia dotyczące szyfrowania treści plików mechanizmem EFS:',
    'answers': [
      {
        'text':
          'każdy plik szyfrowany jest kluczem publicznym właściciela pliku',
        'correct': false,
      },
      { 'text': 'każdy plik szyfrowany jest innym kluczem', 'correct': true },
      {
        'text':
          'plik udostępniony przez właściciela 2 innym użytkownikom jest szyfrowany 3 kluczami',
        'correct': true,
      },
      {
        'text':
          'każdy plik szyfrowany jest kluczem prywatnym właściciela pliku',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '412. Który opis pasuje do poniższej konfiguracji TCP wrappera: ftpd: ALL EXCEPT www : ALLOW ALL : ALL : twist /bin/echo "OK"',
    'answers': [
      {
        'text':
          'za wyjątkiem komputera www umożliwia każdemu dostęp do każdej usługi',
        'correct': false,
      },
      {
        'text': 'zabrania dostępu do usługi WWW z komputera ftpd',
        'correct': false,
      },
      {
        'text': 'umożliwia dostęp do usługi FTP z komputera www',
        'correct': false,
      },
      {
        'text': 'zabrania dostępu do usługi FTP z komputera www',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '413. Pliki zwirtualizowane mechanizmem UAC przechowywane są w systemie Windows w:',
    'answers': [
      {
        'text': 'katalogu "%WINDIR%\\User Access Container\\Sandbox"',
        'correct': false,
      },
      { 'text': 'katalogu "%SYSTEMDRIVE%\\VirtualStore"', 'correct': false },
      {
        'text': 'katalogu "VirtualStore" lokalnym dla każdego użytkownika',
        'correct': true,
      },
      {
        'text': 'alternatywnych strumieniach danych (ADS) systemu NTFS',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '415. Polecenie netsh advfirewall firewall add rule name="private" protocol=icmpv4 action=block dir=out remoteip=10.10.0.2 blokuje:',
    'answers': [
      {
        'text':
          'pingowania adresu 10.10.0.2 niezależnie od użycia IPv4 czy IPv6',
        'correct': false,
      },
      {
        'text': 'pingowania adresu 10.10.0.2 tylko w sieci o profily prywatnym',
        'correct': false,
      },
      {
        'text':
          'pingowania tylko po IPv4 bieżącego systemu z adresu 10.10.0.2 (bez wpływu na IPv6)',
        'correct': false,
      },
      {
        'text':
          'pingowania tylko po IPv4 adresu z bieżącego system 10.10.0.2 (bez wpływu na IPv6)',
        'correct': true,
      },
    ],
  },
  {
    'text':
      '420. Które z poniższych protokołów służą do realizacji kryptograficznych tuneli wirtualnych:',
    'answers': [
      { 'text': 'TLS', 'correct': true },
      { 'text': 'SSO', 'correct': false },
      { 'text': 'IKE', 'correct': true },
      { 'text': 'ESP', 'correct': true },
    ],
  },
  {
    'text':
      '426. Wskaż mechanizmy wykorzystywane do realizacji kontroli dostępu w systemie plików:',
    'answers': [
      { 'text': 'Trustees', 'correct': true },
      { 'text': 'SSO', 'correct': false },
      { 'text': 'ACL', 'correct': true },
      { 'text': 'NTLM', 'correct': false },
    ],
  },
  {
    'text':
      '427. Wskaż mechanizmy wykorzystywane w systemie Windows do ochrony haseł użytkowników:',
    'answers': [
      { 'text': 'Access Control Lists', 'correct': false },
      { 'text': 'Virtualization-Based Security', 'correct': true },
      { 'text': 'Encrypted File System', 'correct': false },
      { 'text': 'Pass the Hash', 'correct': false },
    ],
  },
  {
    'text':
      '8. Mechanizm filtrów eBPF umożliwia wykonanie na odebranym datagramie IP wykonanie następujących operacji zanim pakiet zostanie dostarczony do jądra systemu operacyjnego:',
    'answers': [
      { 'text': 'odrzucenie datagramu', 'correct': true },
      { 'text': 'zmodyfikowanie nagłówka datagramu', 'correct': true },
      { 'text': 'zmodyfikowanie treści datagramu', 'correct': true },
      { 'text': 'przesłanie datagramu do innego komputera', 'correct': true },
    ],
  },
  {
    'text':
      'Plik użytkownika systemu Windows, który został zwirtualizowany mechanizmem UAC, jest widoczny w postaci zwirtualizowanej:',
    'answers': [
      {
        'text': 'dla wszystkich zwirtualizowanych aplikacji w systemie',
        'correct': false,
      },
      {
        'text': 'dla wszystkich zwirtualizowanych aplikacji tego użytkownika',
        'correct': true,
      },
      {
        'text':
          'dla wszystkich aplikacji pracujących aktualnie na tym samym poziomie integralności',
        'correct': false,
      },
      { 'text': 'tylko dla aplikacji która go utworzyła', 'correct': false },
    ],
  },
  {
    'text':
      'Które stwierdzenia są prawdziwe w odniesieniu do wirtualizacji UAC systemu plików w systemie Windows:',
    'answers': [
      {
        'text':
          'każdy zwirtualizowany proces, którego uprawnienia nie pozwalają na dostęp do danego katalogu, otrzyma własną kopię katalogu',
        'correct': false,
      },
      {
        'text':
          'zmiany dla katalogów objętych wirtualizacją są zatwierdzane i wprowadzane do oryginałów każdorazowo po zakończeniu zwirtualizowanego procesu, na zasadzie "ostatni zapis wygrywa"',
        'correct': false,
      },
      {
        'text':
          'wszystkie zwirtualizowane procesy tego samego użytkownika współdzielą ten sam obraz zwirtualizowanego katalogu',
        'correct': true,
      },
      {
        'text':
          'dla katalogów, dla których włączono wirtualizację, każdy proces niezależnie od poziomu integralności otrzyma własną kopię katalogu',
        'correct': false,
      },
    ],
  },
  {
    'text':
      'Wskaż mechanizmy wykorzystywane w systemie Windows do ochrony haseł użytkowników:',
    'answers': [
      { 'text': 'Access Control Lists', 'correct': false },
      { 'text': 'Virtualization-Based Security', 'correct': true },
      { 'text': 'Encrypted File System', 'correct': false },
      { 'text': 'Pass the Hash', 'correct': false },
    ],
  },
  {
    'text':
      'Użytkownik U systemu MS Windows należący do grupy G1 oraz G2 uzyskał jawnie do zasobu O w systemie plików NTFS prawo A, B oraz C. Grupie G1 na liście ACL zasobu O nadano prawo A i D, lecz odmówiono prawa B, natomiast grupa G2 dziedziczy z obiektu nadrzędnego względem O prawo B, C oraz E. Jakie czynne uprawnienia do O posiada U?',
    'answers': [
      { 'text': 'tylko A B C', 'correct': false },
      { 'text': 'tylko A C D', 'correct': false },
      { 'text': 'tylko A C D E', 'correct': true },
      { 'text': 'A B C D E', 'correct': false },
    ],
  },
  {
    'text': 'Uprawnienia domyślne POSIX ACL oznaczają:',
    'answers': [
      {
        'text':
          'uprawnienia nadawane nowym elementom utworzonym w danym katalogu',
        'correct': true,
      },
      {
        'text':
          'minimalne uprawnienia do danego obiektu dla wszystkich użytkowników',
        'correct': false,
      },
      {
        'text': 'uprawnienia obowiązujące użytkowników spoza listy ACL',
        'correct': false,
      },
      {
        'text': 'uprawnienia ustawiane po wyczyszczeniu listy ACL (setfacl -b)',
        'correct': false,
      },
    ],
  },
  {
    'text':
      'W przypadku systemu kontroli ACL standardu POSIX użytkownik U należący do grupy G posiada efektywne uprawnienie r do zasobu p jeśli:',
    'answers': [
      {
        'text':
          'właściciel p ma prawo r oraz p posiada ustawiony bit suid - bez względu na zawartość ACL',
        'correct': false,
      },
      { 'text': 'prawo r zostanie jawnie nadane U lub G', 'correct': true },
      {
        'text':
          'U oraz G występują na liście ACL bez prawa r, ale kategoria "wszyscy użytkownicy" (others) takie uprawnienie posiada',
        'correct': false,
      },
      {
        'text': 'U jest właścicielem p - bez względu na zawartość ACL',
        'correct': false,
      },
    ],
  },
  {
    'text':
      'Wskaż mechanizmy wykorzystywane do realizacji kontroli dostępu w systemie plików:',
    'answers': [
      { 'text': 'Trustees', 'correct': false },
      { 'text': 'SSO', 'correct': false },
      { 'text': 'ACL', 'correct': true },
      { 'text': 'NTLM', 'correct': false },
    ],
  },
  {
    'text':
      'Jeśli w systemie zostanie wykonana komenda: iptables -A INPUT -p tcp --dport ssh -j DROP -s 222.22.22.0/24 to (wyłącznie na jej podstawie) można stwierdzić iż:',
    'answers': [
      {
        'text': 'tylko połączenia SSH z sieci 222.22.22.0/24 będą dopuszczone',
        'correct': false,
      },
      {
        'text':
          'z każdego zdalnego komputera można będzie się zalogować w tym systemie przez SSH',
        'correct': false,
      },
      {
        'text': 'połączenia SSH z sieci 222.22.22.0/24 będą odrzucane',
        'correct': true,
      },
      {
        'text':
          'cała komunikacja SSH niezależnie od adresu źródłowego będzie odrzucana',
        'correct': false,
      },
    ],
  },
  {
    'text':
      'Jak iptables umożliwia wprowadzenie zasady domyślnej odmowy dostępu?',
    'answers': [
      {
        'text': 'umożliwia globalnie dla całej zapory opcją -D (default) DROP',
        'correct': false,
      },
      { 'text': 'nie umożliwia', 'correct': false },
      {
        'text':
          'poprzez prowadzenie odpowiedniej pierwszej reguły w łańcuchu pasującej do każdego pakietu z opcją -P REJECT',
        'correct': false,
      },
      {
        'text':
          'dla konkretnego łańcucha reguł umożliwia prowadzenie polityki DROP',
        'correct': true,
      },
    ],
  },
  {
    'text':
      'Czy iptables umożliwia ograniczenie dostępu do pojedynczej usługi?',
    'answers': [
      {
        'text':
          'nie, sieciowa zapora operuje na pakietach i nie rozróżnia poszczególnych usług',
        'correct': false,
      },
      {
        'text': 'tak, jeśli w regule określimy konkretny protokół',
        'correct': false,
      },
      {
        'text':
          'nie, jeśli w regule określimy konkretny protokół (wówczas reguła dotyczy wszystkich usług wykorzystujących ten protokół)',
        'correct': false,
      },
      {
        'text': 'tak, poprzez wyspecyfikowanie konkretnego portu',
        'correct': true,
      },
    ],
  },
  {
    'text': 'Połączenie VPN w systemie MS Windows:',
    'answers': [
      { 'text': 'może wykorzystywać protokół SMB', 'correct': false },
      {
        'text': 'można skonfigurować w lokalnej polityce bezpieczeństwa',
        'correct': false,
      },
      { 'text': 'można skonfigurować w zaporze sieciowej', 'correct': false },
      { 'text': 'może wykorzystywać protokół IPsec', 'correct': true },
    ],
  },
  {
    'text': 'OpenVPN to:',
    'answers': [
      {
        'text': 'moduł serwera HTTP szyfrujący połączenia z klientami',
        'correct': false,
      },
      {
        'text':
          'sieć VPN o architekturze klient-serwer wykorzystująca kryptosystem OpenSSL i wirtualne interfejsy sieciowe',
        'correct': true,
      },
      {
        'text': 'tunel VPN, który nie wymaga uwierzytelniania stron tunelu',
        'correct': false,
      },
      {
        'text': 'realizacja sieci VPN w oparciu o protokół TLS',
        'correct': false,
      },
    ],
  },
  {
    'text': 'W przypadku użycia IPsec w systemie Windows:',
    'answers': [
      {
        'text':
          'AH nie jest wykorzystywany ani w domyślnych ustawieniach zapory, ani polityki IPsec',
        'correct': false,
      },
      {
        'text':
          'reguły IPsec zdefiniowane w zaporze domyślnie odrzucają cały ruch przychodzący',
        'correct': false,
      },
      {
        'text':
          'reguły IPsec zdefiniowane w zaporze nie szyfrują domyślnie ruchu',
        'correct': true,
      },
      {
        'text':
          'reguły IPsec zdefiniowane w zaporze domyślnie wykorzystują tylko protokół AH',
        'correct': false,
      },
    ],
  },
  {
    'text':
      'Które konfiguracje protokołu IPsec są aktualnie obsługiwane w systemie Windows?',
    'answers': [
      { 'text': 'szyfrowanie ESP i podpis AH', 'correct': true },
      { 'text': 'tryb transportowy i tunelowy z ESP', 'correct': false },
      { 'text': 'tylko AH, bez ESP', 'correct': false },
      { 'text': 'szyfrowanie i podpis ESP, bez AH', 'correct': false },
    ],
  },
  {
    'text': 'Użycie IPsec wraz z IKE wprost chroni przed atakiem:',
    'answers': [
      { 'text': 'TCP spoofing', 'correct': false },
      { 'text': 'ARP cache poisoning', 'correct': false },
      { 'text': 'session hijacking', 'correct': true },
      { 'text': 'name spoofing', 'correct': false },
    ],
  },
  {
    'text':
      'Mechanizm filtrów eBPF umożliwia wykonanie na odebranym datagramie IP wykonanie następujących operacji zanim pakiet zostanie dostarczony do jądra systemu operacyjnego:',
    'answers': [
      { 'text': 'odrzucenie datagramu', 'correct': true },
      { 'text': 'zmodyfikowanie nagłówka datagramu', 'correct': false },
      { 'text': 'zmodyfikowanie treści datagramu', 'correct': false },
      { 'text': 'przesłanie datagramu do innego komputera', 'correct': false },
    ],
  },
  {
    'text':
      'Które stwierdzenia są prawdziwe w odniesieniu do modelu MIC ochrony integralności:',
    'answers': [
      {
        'text':
          'podmiot nie może modyfikować obiektów o wyższym poziomie integralności',
        'correct': true,
      },
      {
        'text':
          'podmiot nie może modyfikować obiektów o niższym poziomie integralności',
        'correct': false,
      },
      {
        'text':
          'podmiot bez uprawnień administracyjnych nie może modyfikować żadnych obiektów o zdefiniowanym poziomie integralności',
        'correct': false,
      },
      {
        'text':
          'podmiot nie może uruchamiać obiektów o niższym poziomie integralności',
        'correct': false,
      },
    ],
  },
  {
    'text':
      'Które z poniższych protokołów realizują kryptograficzne tunele wirtualne z ochroną integralności:',
    'answers': [
      { 'text': 'AH', 'correct': true },
      { 'text': 'ESP', 'correct': true },
      { 'text': 'S/MIME', 'correct': false },
      { 'text': 'TLS', 'correct': false },
    ],
  },
  {
    'text':
      'Które z poniższych protokołów realizują kryptograficzne tunele wirtualne z ochroną poufności:',
    'answers': [
      { 'text': 'PEM', 'correct': false },
      { 'text': 'TLS', 'correct': false },
      { 'text': 'ESP', 'correct': true },
      { 'text': 'S/MIME', 'correct': false },
    ],
  },
  {
    'text':
      'Kto może jako pierwszy dla danego pliku zaszyfrować ten plik mechanizmem EFS:',
    'answers': [
      {
        'text': 'każdy agent DRA, niezależnie od praw dostępu do pliku',
        'correct': false,
      },
      {
        'text': 'każdy kto posiada prawo modyfikacji pliku',
        'correct': true,
      },
      {
        'text': 'tylko właściciel pliku',
        'correct': false,
      },
      {
        'text': 'każdy administrator, niezależnie od praw dostępu do pliku',
        'correct': false,
      },
    ],
  },
  {
    'text': 'Nowoutworzony katalog w systemie Linux:',
    'answers': [
      {
        'text':
          'na liście ACL otrzyma skopiowane z katalogu nadrzędnego uprawnienia domyślne jako wpisy ACE',
        'correct': true,
      },
      {
        'text':
          'na liście ACL otrzyma skopiowane z katalogu nadrzędnego uprawnienia domyślne jako wpisy DefaultACE',
        'correct': false,
      },
      {
        'text':
          "na liście ACL otrzyma skopiowane wszystkie prawa efektywne oprócz prawa 'x' jako wpisy ACE",
        'correct': false,
      },
      {
        'text': 'zawsze otrzyma pustą listę ACL',
        'correct': false,
      },
    ],
  },
  {
    'text':
      'Klucz szyfrowania, którym zaszyfrowana została treść pliku (standardowym mechanizmem EFS systemu NTFS):',
    'answers': [
      {
        'text':
          'jest kluczem symetrycznym należącym do użytkownika, który zaszyfrował plik i znajduje się w certyfikacie EFS tego użytkownika',
        'correct': false,
      },
      {
        'text':
          'jest jednorazowym kluczem symetrycznym używanym wyłącznie na potrzeby szyfrowania i deszyfrowania tylko tego pliku',
        'correct': true,
      },
      {
        'text': 'jest kluczem publicznym właściciela pliku',
        'correct': false,
      },
      {
        'text': 'jest kluczem prywatnym właściciela pliku',
        'correct': false,
      },
    ],
  },
  {
    'text':
      'Które stwierdzenia dotyczące blokady konta użytkownika w systemie Windows są prawdziwe:',
    'answers': [
      {
        'text':
          'licznik prób logowania jest zerowany po każdym pomyślnym zalogowaniu',
        'correct': true,
      },
      {
        'text':
          'licznik prób logowania jest zerowany po każdym nieudanym logowaniu',
        'correct': false,
      },
      {
        'text': 'licznik prób logowania może wyzerować administrator',
        'correct': true,
      },
      {
        'text':
          'licznik prób logowania jest zerowany automatycznie po zadanym czasie',
        'correct': true,
      },
    ],
  },
  {
    'text':
      'Dany jest plik Tajne.txt. Załóżmy, że użytkownik Adaś należy do grupy Users oraz Administrators. Plik Tajne.txt ma przydzielone uprawnienia ACL: ALLOW na czytanie i DENY na zapis dla grupy Users, oraz jawnie przydzielone ALLOW na zapis dla użytkownika Adaś, oraz jawnie przydzielone ALLOW na "full control" dla grupy Administrators. Jakie uprawnienia ostatecznie ma Adaś do pliku Tajne.txt?',
    'answers': [
      {
        'text': 'ma uprawnienia do zapisu, brak uprawnienia do odczytu',
        'correct': false,
      },
      {
        'text': 'ma uprawnienia do odczytu, brak uprawnień do zapisu',
        'correct': true,
      },
      {
        'text': 'brak uprawnień do odczytu i zapisu',
        'correct': false,
      },
      {
        'text': 'ma uprawnienia do odczytu i zapisu',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '8. $ getfacl test\nuser::rwx\nuser:jbond:rwx\ngroup::r--\ngroup:agents:r-x\nother::---\nmask::r-x\ndefault:user::rwx\ndefault:user:jbond:r-x\ndefault:group:-wx\ndefault:group:agents:-wx\ndefault:other::r-x\ndefault:mask::--x\nOznacza, że:',
    'answers': [
      {
        'text': 'grupa agents może modyfikować zawartość obiektu test',
        'correct': false,
      },
      {
        'text': 'użytkownik jbond może tworzyć pliki w katalogu test',
        'correct': false,
      },
      {
        'text': 'użytkownik jbond może przeglądać listę plików w katalogu test',
        'correct': true,
      },
      {
        'text':
          'grupa agents może tworzyć nowe pliki w nowych podkatalogach katalogu test',
        'correct': false,
      },
    ],
  },
  {
    'text':
      '3. $ getfacl test\nuser::rwx\nuser:jbond:rwx\ngroup::r--\ngroup:agents:r-x\nmask::r-x\nother::---\ndefault:user::rwx\ndefault:user:jbond:r-x\ndefault:group::-wx\ndefault:group:agents:-wx\ndefault:other::r-x\ndefault:mask::--x\nOznacza, że:',
    'answers': [
      {
        'text': 'grupa agents może modyfikować zawartość obiektu test',
        'correct': false,
      },
      {
        'text': 'właściciel może tworzyć pliki w katalogu test',
        'correct': true,
      },
      {
        'text': 'użytkownik jbond może przeglądać listę plików w katalogu test',
        'correct': true,
      },
      {
        'text': 'użytkownik jbond może modyfikować zawartość obiektu test',
        'correct': false,
      },
    ],
  },
];
