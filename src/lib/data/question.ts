export const questions = [
  {
    text: '1. Sieci VPN można zbudować wykorzystując:',
    answers: [
      { text: 'IDS', correct: false },
      { text: 'Wireguard', correct: true },
      { text: 'TLS', correct: true },
      { text: 'SIEM', correct: false },
    ],
  },
  {
    text: '2. Użytkownik Windows, będący administratorem, po zalogowaniu się do systemu:',
    answers: [
      {
        text: 'otrzyma pełny token uprawnień i zawsze będzie korzystał z pełnego tokenu',
        correct: false,
      },
      {
        text: 'otrzyma token pełny i ograniczony, zawsze będzie korzystał z pełnego tokenu',
        correct: false,
      },
      {
        text: 'otrzyma token pełny i ograniczony, będzie mógł korzystać z jednego lub drugiego',
        correct: true,
      },
      {
        text: 'otrzyma tylko token ograniczony, ale będzie mógł wykorzystać pełny token przy użyciu mechanizmu impersonation',
        correct: false,
      },
    ],
  },
  {
    text: '3. Metoda Diffiego-Hellmana:',
    answers: [
      {
        text: 'pozwala bezpiecznie składować klucze prywatne użytkowników',
        correct: false,
      },
      { text: 'jest odporna na ataki pasywne', correct: true },
      { text: 'jest odporna na ataki aktywne', correct: false },
      {
        text: 'pozwala bezpiecznie dystrybuować klucze publiczne użytkowników',
        correct: false,
      },
      {
        text: 'wykorzystuje ideę asymetrycznej pary kluczy (prywatny-publiczny)',
        correct: false,
      },
      { text: 'generuje programowo hasła SSO', correct: false },
      { text: 'pozwala wygenerować symetryczny klucz sesji', correct: true },
      {
        text: 'realizuje uwierzytelnianie metodą haseł jednorazowych',
        correct: false,
      },
    ],
  },
  {
    text: '4. Usługa DNSsec:',
    answers: [
      {
        text: 'wykorzystuje IPsec do tunelowania zapytań i odpowiedzi DNS',
        correct: false,
      },
      {
        text: 'wykorzystuje SSL do tunelowania zapytań i odpowiedzi DNS',
        correct: false,
      },
      { text: 'wymaga podpisanych cyfrowo zapytań DNS', correct: false },
      { text: 'stosuje podpisy cyfrowe odpowiedzi DNS', correct: true },
    ],
  },
  {
    text: '5. Które metody uwierzytelniania stosuje protokół HTTP/1.1:',
    answers: [
      { text: 'tylko użycie jednokierunkowej funkcji skrótu', correct: false },
      { text: 'tylko username-password', correct: false },
      {
        text: 'zarówno username-password jak i użycie funkcji skrótu, ale nie certyfikaty X.509',
        correct: true,
      },
      {
        text: 'zarówno username-password, funkcją skrótu, jak i certyfikaty X.509',
        correct: false,
      },
    ],
  },
  {
    text: '6. Które komponenty systemu operacyjnego Windows mogą korzystać ze sprzętowej wirtualizacji celem podniesienia bezpieczeństwa systemu:',
    answers: [
      { text: 'Alpine docker containers', correct: false },
      { text: 'Defender Application Guard', correct: true },
      { text: 'AppContainer', correct: false },
      { text: 'Ring - 1 compartmentalization', correct: false },
    ],
  },
  {
    text: '7. Wskaż mechanizmy chroniące m.in. przed atakami przepełnienia bufora:',
    answers: [
      {
        text: 'wykorzystanie Structured Exception Handling i Vectored Exception Handling',
        correct: false,
      },
      {
        text: 'zapewnienie by segment pamięci z prawem zapisu nie posiadał jednocześnie prawa wykonywania',
        correct: true,
      },
      {
        text: 'randomizacja alokacji wirtualnej przestrzeni adresowej procesu',
        correct: true,
      },
      {
        text: 'alokowanie na stosie dodatkowego elementu ramki funkcji wykrywającego modyfikację adresu powrotu',
        correct: true,
      },
    ],
  },
  {
    text: '8. Mechanizm two-factor authentication (2FA):',
    answers: [
      {
        text: 'wymaga użycia 2 oddzielnych operacji (oraz danych) uwierzytelniających',
        correct: true,
      },
      {
        text: 'dotyczy złożoności hasła i wymaga by nowe hasło różniło się od dotychczasowego na 2 pozycjach',
        correct: false,
      },
      { text: 'to uwierzytelnianie z zaufaną stroną trzecią', correct: false },
      { text: 'to uwierzytelnianie metodą zawołanie-odzew', correct: false },
    ],
  },
  {
    text: '9. System Kerberos oferuje:',
    answers: [
      {
        text: 'kryptograficzne uwierzytelnianie użytkowników w ramach domeny',
        correct: true,
      },
      {
        text: 'delegowanie uprawnień jednego podmiotu innym podmiotom',
        correct: true,
      },
      {
        text: 'zastosowanie kryptograficznego weryfikatora w celu ochrony przed atakiem Golden Ticket',
        correct: false,
      },
      {
        text: 'uwierzytelnianie użytkowników pomiędzy domenami',
        correct: true,
      },
    ],
  },
  {
    text: '10. Komputer-Twierdza:',
    answers: [
      {
        text: 'dopuszcza komunikację przechodzącą tylko przez usługi proxy',
        correct: true,
      },
      {
        text: 'to rodzaj zapory sieciowej z filtracją pakietów i modułem IDS',
        correct: false,
      },
      {
        text: 'jest implementacją zapory typu Application Layer Gateway',
        correct: false,
      },
      {
        text: 'pełni rolę zaufanej strony trzeciej w domenie Kerberos',
        correct: false,
      },
    ],
  },
  {
    text: '11. Które komponenty sprzętowe służą (między innymi) do bezpiecznego przechowywania materiału kryptograficznego:',
    answers: [
      { text: 'IEEE 1609.2', correct: false },
      { text: 'X.509', correct: false },
      { text: 'EFS', correct: false },
      { text: 'Trusted Platform Module', correct: true },
    ],
  },
  {
    text: '12. Model CAP kontroli dostępu:',
    answers: [
      {
        text: 'jest stosowany w systemach MIC (Mandatory Integrity Control)',
        correct: false,
      },
      {
        text: 'jest stosowany w systemach RBAC (Role-Based Access Control)',
        correct: false,
      },
      { text: 'uprawnienia dostępu wiąże z podmiotami', correct: true },
      { text: 'uprawnienia dostępu wiąże z zasobami', correct: false },
    ],
  },
  {
    text: '13. Model kontroli dostępu MAC zabrania podmiotowi o etykiecie P:',
    answers: [
      { text: 'odczytu obiektu o niższej etykiecie niż P', correct: false },
      { text: 'zapisu obiektu o wyższej etykiecie niż P', correct: false },
      { text: 'odczytu obiektu o wyższej etykiecie niż P', correct: true },
    ],
  },
  {
    text: '14. Wskaż protokoły i standardy dokonujące uwierzytelniania dostępu do sieci, działające między klientem sieci (komputerem) a punktem (serwerem) dostępowym:',
    answers: [
      { text: 'IEEE 802.1X', correct: true },
      { text: 'TACACS', correct: false },
      { text: 'RADIUS', correct: false },
      { text: 'EAP', correct: true },
    ],
  },
  {
    text: '15. Protokół Kerberos:',
    answers: [
      {
        text: 'pozwala osiągnąć obustronne uwierzytelnienie klienta usługi sieciowej i serwera tej usługi',
        correct: true,
      },
      {
        text: 'realizuje uwierzytelnianie w modelu z zaufaną stroną trzecią',
        correct: true,
      },
      {
        text: 'realizuje uwierzytelnianie kryptograficzne z wykorzystaniem kluczy symetrycznych',
        correct: true,
      },
      {
        text: 'realizuje uwierzytelnianie SSO w środowisku domenowym',
        correct: true,
      },
    ],
  },
  {
    text: '16. Wskaż możliwe prawidłowe reakcje na wykrycie faktu przepełnienia bufora (w segmencie stosu) umożliwiające zachowanie bezpieczeństwa systemu:',
    answers: [
      {
        text: 'ponowne zainicjowanie bufora domyślną wartością',
        correct: false,
      },
      {
        text: 'usunięcie danych wykraczających poza bufor, zanim zostaną odczytane',
        correct: false,
      },
      { text: 'natychmiastowe przerwanie działania procesu', correct: true },
      {
        text: 'zapisanie zaraz za nadmiernymi danymi "kanarka" ostrzegającego o wystąpieniu przepełniania przy próbie odczytu bufora',
        correct: false,
      },
    ],
  },
  {
    text: '17. Systemy nadzoru NAC (Network Access Control):',
    answers: [
      {
        text: 'dokonują uwierzytelniania stanowisk sieciowych przed dopuszczeniem ich do sieci lokalnej',
        correct: true,
      },
      {
        text: 'wykrywają pakiety na podstawie analizy behawioralnej i uczenia maszynowego',
        correct: false,
      },
      {
        text: 'dopuszczają stanowiska do sieci lokalnej po weryfikacji zgodności ich konfiguracji z polityką bezpieczeństwa',
        correct: true,
      },
      {
        text: 'wykrywają podejrzane pakiety na podstawie sygnatur ataków sieciowych',
        correct: false,
      },
    ],
  },
  {
    text: '18. Protokół SSL/TLS:',
    answers: [
      {
        text: 'pozwala uwierzytelniać kryptograficznie zarówno klienta, jak i serwer',
        correct: true,
      },
      {
        text: 'nigdy nie uwierzytelnia klienta, to zadanie wyłącznie protokołu aplikacyjnego, np. HTTP',
        correct: false,
      },
      {
        text: 'nigdy nie dokonuje uwierzytelniania, zostawiając to zadanie innym protokołom, np. ISAKMP',
        correct: false,
      },
      {
        text: 'kryptograficznie uwierzytelnia tylko serwer, klienta tylko hasłem',
        correct: false,
      },
    ],
  },
  {
    text: '19. Wskaż prawdziwe stwierdzenia dotyczące bramy aplikacyjnej Application Layer Gateway:',
    answers: [
      {
        text: 'pośredniczy w komunikacji wyłącznie na poziomie warstwy aplikacyjnej',
        correct: true,
      },
      {
        text: 'optymalizuje ruch stosując filtrację kontekstową na podstawie tablicy aktywnych połączeń',
        correct: false,
      },
      {
        text: 'wymaga działającego poprawnie routingu między interfejsami sieciowymi',
        correct: false,
      },
      {
        text: 'filtruje pakiety na poziomie wszystkich 3 warstw: sieciowej, transportowej i aplikacyjnej',
        correct: true,
      },
    ],
  },
  {
    text: '20. Które z poniższych algorytmów kryptograficznych mogą w praktyce zostać wykorzystane do zaszyfrowania treści listu e-mail:',
    answers: [
      { text: 'AES', correct: true },
      { text: 'RSA', correct: false },
      { text: 'Twofish', correct: true },
      { text: 'Blowfish', correct: true },
    ],
  },
  {
    text: '21. Technologie umożliwiające ochronę integralności transmitowanych danych to m.in:',
    answers: [
      { text: 'protokół TLS', correct: true },
      { text: 'protokół AH', correct: true },
      { text: 'protokół ESP', correct: true },
      { text: 'SYN cookies', correct: false },
    ],
  },
  {
    text: '22. Szyfrowanie asymetryczne zapewnia:',
    answers: [
      {
        text: 'autentyczność pod warunkiem zachowania tajności klucza prywatnego odbiorcy',
        correct: false,
      },
      {
        text: 'poufność pod warunkiem zachowania tajności klucza prywatnego nadawcy',
        correct: false,
      },
      {
        text: 'poufność pod warunkiem zachowania tajności klucza prywatnego odbiorcy',
        correct: true,
      },
      {
        text: 'autentyczność pod warunkiem zachowania tajności klucza prywatnego nadawcy',
        correct: true,
      },
    ],
  },
  {
    text: '23. Algorytm Lamporta, leżący u podstaw koncepcji programowej generacji haseł jednorazowych:',
    answers: [
      { text: 'wymaga użycia funkcji jednokierunkowej', correct: true },
      {
        text: 'wymaga rozwiązania problemu rozproszonego konsensusu',
        correct: false,
      },
      {
        text: 'wymaga wykorzystania kryptografii asymetrycznej',
        correct: false,
      },
      {
        text: 'wymaga rozwiązania problemu rozproszonego wzajemnego wykluczania',
        correct: false,
      },
    ],
  },
  {
    text: '24. Wskaż mechanizmy systemu operacyjnego będące realizacją (choćby częściową) koncepcji piaskownicy:',
    answers: [
      { text: 'Windows AppContainer', correct: true },
      { text: 'SSL/TLS', correct: false },
      { text: 'click-jacking', correct: false },
      { text: 'wirtualizacja systemu operacyjnego', correct: true },
    ],
  },
  {
    text: '25. Pewna zapora sieciowa filtrująca pakiety realizuje jednocześnie funkcje NAT. Które opisy pasują do takiej zapory:',
    answers: [
      {
        text: 'filtracja DNAT może być dokonywana dla pakietów przechodzących przez zaporę niezależnie od kierunku',
        correct: false,
      },
      {
        text: 'translacja DNAT musi być dokonana przed routingiem pakietu aby pozycje tablicy routingu mogły być prawidłowo dopasowane',
        correct: true,
      },
      {
        text: 'translacja DNAT musi być dokonana przed filtracją pakietu na interfejsie wejściowym, aby reguły łańcucha wejściowego mogły być prawidłowo dopasowane',
        correct: false,
      },
      {
        text: 'translacja SNAT musi być dokonana przed filtracją kontekstową na interfejsie wyjściowym, aby pakiet znalazł prawidłowe dopasowanie do tablicy aktywnych połączeń',
        correct: false,
      },
    ],
  },
  {
    text: '26. Jakie cechy wirtualizacji są istotne dla bezpieczeństwa systemu?',
    answers: [
      {
        text: 'procesor utrudnia ucieczkę ze środowiska zwirtualizowanego poprzez ochronę komend hipervisora na poziomie Ring -1',
        correct: true,
      },
      {
        text: 'wirtualizacja systemu operacyjnego daje efekt piaskownicy dla uruchomionych w tym systemie aplikacji',
        correct: true,
      },
      {
        text: 'hypervisor pośredniczy w wywołaniach funkcji jądra systemu operacyjnego, więc może wychwytywać potencjalnie niebezpieczne zachowania',
        correct: false,
      },
      {
        text: 'w systemie wirtualnym bezpośredni dostęp do pamięci fizycznej (w tym pamięci urządzeń I/O) nie jest możliwy nawet dla rozkazów Ring 0, co ułatwia izolację maszyn wirtualnych nawet w przypadku przejęcia uprawnień administracyjnych wewnątrz dowolnej z nich',
        correct: true,
      },
    ],
  },
  {
    text: '27. Które z poniższych cech dotyczą szyfrowania asymetrycznego:',
    answers: [
      { text: 'odporność na kolizje', correct: false },
      {
        text: 'gwarancja autentyczności i niezaprzeczalności komunikacji',
        correct: true,
      },
      {
        text: 'większa niż dla algorytmów symetrycznych efektywność',
        correct: false,
      },
    ],
  },
  {
    text: '28. Które z poniższych cech dotyczą szyfrowania symetrycznego:',
    answers: [
      { text: 'odporność na kolizje', correct: false },
      {
        text: 'gwarancja autentyczności i niezaprzeczalności komunikacji',
        correct: false,
      },
      {
        text: 'większa niż dla algorytmów asymetrycznych efektywność',
        correct: true,
      },
    ],
  },
  {
    text: '29. Które z poniższych mechanizmów pozwalają w systemie operacyjnym na chwilowe uzyskanie innych uprawnień dostępu niż posiadane aktualnie przez użytkownika:',
    answers: [
      { text: 'Windows UAC', correct: true },
      { text: 'POSIX ACL', correct: false },
      { text: 'sudo', correct: true },
      { text: 'POSIX CAP', correct: true },
    ],
  },
  {
    text: '30. Wskaż cechy mechanizmu AppContainer:',
    answers: [
      {
        text: 'kontroluje wywołania funkcji jądra systemu operacyjnego',
        correct: false,
      },
      {
        text: 'jest "lekkim" odpowiednikiem maszyny wirtualnej, z tą różnicą, że nie zawiera zwirtualizowanego systemu operacyjnego, tylko aplikację i potrzebne biblioteki',
        correct: false,
      },
      {
        text: 'wykorzystuje wirtualizację systemu plików i rejestru systemu Windows',
        correct: true,
      },
      {
        text: 'jest rodzajem kwarantanny dla potencjalnie zainfekowanych aplikacji, przetrzymywanych tam zanim antywirus otrzyma z chmury ostateczny rezultat analizy behawioralnej podejrzanego kodu',
        correct: false,
      },
    ],
  },
  {
    text: '31. Wskaż cechy charakterystyczne ataku przez przepełnienie bufora (w segmencie stosu):',
    answers: [
      {
        text: 'celem przepełnienia jest nadpisanie adresu powrotu w ramce funkcji odłożonej aktualnie na stosie',
        correct: true,
      },
      {
        text: 'architektura pamięci musi być taka by adresy rosły zgodnie z kierunkiem przyrostu stosu',
        correct: false,
      },
      {
        text: 'celem przepełnienia jest nadpisanie pamięci jądra i wywołanie błędu obsłużonego przez złośliwy kod',
        correct: false,
      },
      {
        text: 'przepełnienie bufora można wykryć i odpowiednio zareagować',
        correct: true,
      },
    ],
  },
  {
    text: '32. Zaznacz cechy charakterystyczne metody ARP detekcji podsłuchu w sieci:',
    answers: [
      {
        text: 'ogłoszenie ARP skierowane pod fałszywy adres IP',
        correct: true,
      },
      {
        text: 'zapytanie ARP skierowane pod właściwy adres MAC odpytywanej stacji',
        correct: false,
      },
      {
        text: 'zapytanie ARP skierowane pod rozgłoszeniowy adres MAC',
        correct: false,
      },
      {
        text: 'zapytanie ARP skierowane pod nierozgłoszeniowy adres MAC',
        correct: true,
      },
    ],
  },
  {
    text: '33. Wskaż problemy bezpieczeństwa wynikające z fragmentacji IP:',
    answers: [
      {
        text: 'fragmentacja jest przyczyną skuteczności ataku SYN flood',
        correct: false,
      },
      {
        text: 'potencjalna możliwość przepełnienia bufora pamięci przy scalaniu fragmentów',
        correct: true,
      },
      {
        text: 'utrudniona możliwość filtracji fragmentów przez zapory sieciowe',
        correct: true,
      },
      {
        text: 'kontrola fragmentacji wymaga użycia ciasteczek SYN cookies',
        correct: false,
      },
    ],
  },
  {
    text: '34. Zaznacz prawdziwe stwierdzenia dotyczące protokołu HTTP:',
    answers: [
      {
        text: 'HTTP od wersji 1.1 uwierzytelnia nie tylko klienta, ale i serwer',
        correct: false,
      },
      {
        text: 'Digest Authentication HTTP 1.1 realizuje metodę challenge-response',
        correct: true,
      },
      {
        text: 'Basic Authentication w HTTP 1.0 przesyła nazwę użytkownika i hasło w postaci niezaszyfrowanej',
        correct: true,
      },
      {
        text: 'Basic Authentication w HTTP 1.1 przesyła nazwę użytkownika i hasło w postaci zaszyfrowanej',
        correct: false,
      },
    ],
  },
  {
    text: '35. Protokół Kerberos:',
    answers: [
      {
        text: 'realizuje uwierzytelnianie SSO w środowisku domenowym',
        correct: true,
      },
      {
        text: 'realizuje uwierzytelnianie SSO w środowisku między-domenowym',
        correct: true,
      },
      {
        text: 'umożliwia uwierzytelnianie i autoryzację klientów usług sieciowych przez scentralizowany mechanizm (serwer KDC)',
        correct: true,
      },
      {
        text: 'nie wymaga znajomości po stronie uwierzytelniającej żadnych danych wrażliwych klienta (Zero-Proof Knowledge)',
        correct: false,
      },
    ],
  },
  {
    text: '36. Które z poniższych cech prawidłowo opisują protokół IPsec?',
    answers: [
      {
        text: 'może działać z uwierzytelnianiem stron dokumentowanym tylko przez ESP',
        correct: false,
      },
      {
        text: 'może działać w trybie tylko z ochroną integralności przez ESP',
        correct: true,
      },
      {
        text: 'może działać z uwierzytelnianiem stron dokumentowanym tylko przez AH',
        correct: false,
      },
      {
        text: 'może działać w trybie tylko z ochroną integralności przez AH',
        correct: true,
      },
    ],
  },
  {
    text: '37. Wskaż cechy uprawnień POSIX CAP:',
    answers: [
      { text: 'mogą być przypisywane do użytkowników', correct: true },
      { text: 'mogą być przypisywane do procesów', correct: true },
      { text: 'podlegają dziedziczeniu przez procesy potomne', correct: true },
      {
        text: 'pozwalają na delegowanie podmiotom wybranych elementarnych uprawnień administracyjnych',
        correct: true,
      },
    ],
  },
  {
    text: '38. Które z poniższych algorytmów kryptograficznych mogą zostać wykorzystane w sieci VPN do szyfrowania transmisji przez protokół SSL/TLS lub IPsec:',
    answers: [
      { text: 'RSA', correct: false },
      { text: 'ECDH', correct: false },
      { text: 'AES', correct: true },
      { text: 'DH', correct: false },
    ],
  },
  {
    text: '39. Które z poniższych cech prawidłowo opisują protokół IKE?',
    answers: [
      {
        text: 'umożliwia zmianę kluczy szyfrowania protokołu IPsec ESP',
        correct: true,
      },
      { text: 'uwierzytelnia sesje SA protokołu IPsec', correct: true },
      { text: 'negocjuje parametry sesji SA protokołu IPsec', correct: true },
      {
        text: 'umożliwia zmianę kluczy szyfrowania protokołu IPsec AH',
        correct: false,
      },
    ],
  },
  {
    text: '40. Tunele OpenVPN:',
    answers: [
      { text: 'stosują protokół ESP do szyfrowania ruchu', correct: false },
      { text: 'stosują protokół AH do szyfrowania ruchu', correct: false },
      { text: 'stosują protokół TLS do szyfrowania ruchu', correct: true },
      {
        text: 'stosują protokół ISAKMP do uwierzytelniania ruchu',
        correct: false,
      },
    ],
  },
  {
    text: '41. Które z poniższych słów kluczowych mogą być prawidłowym "celem" w regule iptables dla łańcucha OUTPUT?',
    answers: [
      { text: 'DROP', correct: true },
      { text: 'FORWARD', correct: false },
      { text: 'XOR', correct: false },
      { text: 'ACCEPT', correct: true },
    ],
  },
  {
    text: '42. Polecenie ulimit:',
    answers: [
      {
        text: 'decyduje o tym czy mogą być tworzone zrzuty przestrzeni adresowej (obrazy) procesów',
        correct: true,
      },
      {
        text: 'podaje bieżące ograniczenia hard i soft, ale pozwala zmienić tylko soft',
        correct: true,
      },
      {
        text: 'podaje bieżące ograniczenia hard i soft, ale nie pozwala ich zmieniać',
        correct: false,
      },
      {
        text: 'pozwala zmienić oba rodzaje limitów: i hard, i soft',
        correct: false,
      },
    ],
  },
  {
    text: '43. Czym się różni twist od spawn w polityce tcp wrappera (np. w pliku hosts.allow)?',
    answers: [
      {
        text: 'spawn służy do zapisywania wiadomości w logu lub wysyłania poczty, natomiast twist wysyła wiadomość i odmawia dostępu do usługi',
        correct: false,
      },
      {
        text: 'oba polecenia użyte w hosts.allow kończą się odmową polecenia, ale twist dodatkowo zapisuje informację o tym w logu systemowym',
        correct: false,
      },
      {
        text: 'twist przekierowuje połączenie do innej, określonej opcją usługi, podczas gdy spawn tworzy nowy proces wykonujący dowolne polecenie',
        correct: false,
      },
      {
        text: 'spawn tworzy nowy proces wykonujący dane polecenie, natomiast twist wykonuje polecenie w ramach bieżącego procesu',
        correct: true,
      },
    ],
  },
  {
    text: '44. Co oznacza udział IPC$ i do czego jest wykorzystywany?',
    answers: [
      {
        text: 'to udział służący w systemie Windows do zdalnego wywołania procedur (RPC)',
        correct: true,
      },
      {
        text: 'to udział domyślny służący do zdalnej administracji systemem Windows',
        correct: false,
      },
      {
        text: 'to udział administracyjny obejmujący wszystkie istniejące lokalne dyski',
        correct: false,
      },
      {
        text: 'to udział kolejek POSIX IPC służący do lokalnej komunikacji między procesami',
        correct: false,
      },
    ],
  },
  {
    text: '45. SSH pozwala:',
    answers: [
      {
        text: 'uwierzytelniać użytkowników z wykorzystaniem kluczy kryptograficznych',
        correct: true,
      },
      {
        text: 'uwierzytelniać użytkowników z wykorzystaniem haseł',
        correct: true,
      },
      {
        text: 'uwierzytelniać komputery (systemy operacyjne) z wykorzystaniem kluczy kryptograficznych',
        correct: true,
      },
      {
        text: 'udostępnić zasoby serwera lokalnego przez przekierowanie portów z serwera zdalnego',
        correct: false,
      },
    ],
  },
  {
    text: '46. Które z poniższych cech dotyczą szyfrowania asymetrycznego:',
    answers: [
      {
        text: 'gwarancja autentyczności i niezaprzeczalności komunikacji',
        correct: true,
      },
      { text: 'odporność na kolizje', correct: false },
      {
        text: 'większa niż dla algorytmów symetrycznych efektywność',
        correct: false,
      },
    ],
  },
  {
    text: '47. W których z poniższych przypadków rekalkulowana jest maska uprawnień ACL w systemie Linux:',
    answers: [
      { text: 'gdy podamy opcję -m dla polecenia setfacl', correct: false },
      {
        text: 'przy zmianie uprawnień właściciela przy pomocy polecenia chmod',
        correct: false,
      },
      {
        text: 'przy każdej zmianie uprawnień poleceniem setfacl, chyba że użyjemy opcji -n',
        correct: true,
      },
      {
        text: 'przy dowolnej zmianie uprawnień danej kategorii praw (np. maska dla grupy modyfikowana jest przy modyfikacji praw dotyczących grupy)',
        correct: false,
      },
    ],
  },
  {
    text: '48. Domyślne udziały administracyjne w systemie Windows:',
    answers: [
      { text: 'dostępne są tylko dla administratora', correct: true },
      {
        text: 'są tworzone automatycznie przy instalacji systemu',
        correct: true,
      },
      { text: 'nie mogą być usunięte', correct: false },
      { text: 'mogą być usunięte', correct: true },
    ],
  },
  {
    text: '49. Aby użytkownik L na komputerze HL mógł logować się bez podawania hasła na komputer HR na konto R należy:',
    answers: [
      {
        text: 'skopiować klucz prywatny użytkownika R z komputera HR do pliku ~/.ssh/authorized_keys na koncie L na komputerze HL',
        correct: false,
      },
      {
        text: 'skopiować klucz publiczny użytkownika L z komputera HL do pliku ~/.ssh/authorized_keys na koncie R na komputerze HR',
        correct: true,
      },
      {
        text: 'skopiować klucz publiczny użytkownika R z komputera HR do pliku ~/.ssh/authorized_keys na koncie L na komputerze HL',
        correct: false,
      },
      {
        text: 'skopiować klucz prywatny użytkownika L z komputera HL do pliku ~/.ssh/authorized_keys na koncie R na komputerze HR',
        correct: false,
      },
    ],
  },
  {
    text: '50. Model kontroli dostępu MIC zabrania podmiotowi o etykiecie P:',
    answers: [
      { text: 'zapisu obiektu o wyższej etykiecie niż P', correct: false },
      { text: 'odczytu obiektu o niższej etykiecie niż P', correct: true },
      { text: 'zapisu obiektu o niższej etykiecie niż P', correct: true },
    ],
  },
  {
    text: '51. Wykorzystanie TCP Wrappera do ochrony określonej usługi jest możliwe:',
    answers: [
      {
        text: 'jeśli program serwera usługi korzysta z biblioteki libwrap.so i sam czyta politykę TCP Wrappera',
        correct: true,
      },
      {
        text: 'automatycznie po definicji polityki (host_access), bowiem TCP Wrapper jest zintegrowany z systemem operacyjnym',
        correct: false,
      },
      {
        text: 'w przypadku przekazania nawiązywanego przez klienta usługi połączenia do demona TCP Wrappera zamiast do serwera obsługującego tę usługę',
        correct: true,
      },
      {
        text: 'dopiero po skonfigurowaniu iptables do przekierowania ruchu na port nasłuchującego superserwera xinetd',
        correct: false,
      },
    ],
  },
  {
    text: '52a. Strumień ADS:',
    answers: [
      {
        text: 'jest częścią nagłówka pliku dołączaną zawsze przez system Windows podczas operacji pakowania do archiwum lub udostępniania w sieci',
        correct: false,
      },
      {
        text: 'jest wykorzystywany przez mechanizm informujący o stopniu zaufania do pliku (określający jego pochodzenie przez wpis ZoneId)',
        correct: true,
      },
      {
        text: 'pozwala związać z dowolnym plikiem lub katalogiem dowolne (zarówno tekstowe, jak i binarne) dane',
        correct: true,
      },
      {
        text: 'jest wykorzystywany przez procesy w systemie Windows do informowania o błędach wykonania (tzw. metainformacje)',
        correct: false,
      },
    ],
  },
  {
    text: '52b. Mechanizm EFS:',
    answers: [
      {
        text: 'zabezpiecza dostęp do treści poszczególnych plików zarówno w czasie działania systemu, jak i po jego wyłączeniu (at rest)',
        correct: true,
      },
      {
        text: 'stosuje kryptografię asymetryczną do szyfrowania treści plików',
        correct: false,
      },
      {
        text: 'realizuje full disc encyption w celu zabezpieczenia systemu operacyjnego przed niepowołanym uruchomieniem i dostępem',
        correct: false,
      },
      { text: 'wymaga do swojego działania konta DRA', correct: false },
    ],
  },
  {
    text: '53. Jakie hasło jest domyślnie wymagane przez polecenie sudo, jeżeli w konfiguracji nie będzie ustawione inaczej:',
    answers: [
      { text: 'administratora systemu', correct: false },
      {
        text: 'właściciela programu (SUID) uruchamianego tym poleceniem',
        correct: false,
      },
      { text: 'hasło puste (domyślnie sudo nie pyta o hasło)', correct: false },
      { text: 'użytkownika wywołującego polecenie sudo', correct: true },
    ],
  },
  {
    text: '54. Gdy w poleceniu iptables nie podamy celu reguły, przy pomocy opcji -j (np. -j REJECT), wówczas:',
    answers: [
      {
        text: 'po dopasowaniu reguły iptables przerywa przetwarzanie, ale pakiet jest przepuszczany',
        correct: false,
      },
      {
        text: 'po dopasowaniu reguły iptables przetwarza kolejne reguły',
        correct: true,
      },
      {
        text: 'używany jest cel domyślny dla danego łańcucha, tzw. polityka (ustawiana przy pomocy -P)',
        correct: false,
      },
      {
        text: 'reguła zostanie odrzucona jako błędna, chyba że jest to modyfikacja wcześniej istniejącej reguły (przy pomocy opcji -R), kiedy to zostanie zastosowany taki cel, jaki był ustawiony dotychczas w tej regule',
        correct: false,
      },
    ],
  },
  {
    text: '55. Impersonation w systemie Windows to:',
    answers: [
      {
        text: 'przypisanie tokenu bezpieczeństwa ogólnego przeznaczenia do konkretnego użytkownika stanowiącego instancję pewnego SID',
        correct: false,
      },
      {
        text: 'rodzaj zdalnego ataku na system, w którym napastnik podszywa się pod jednego z użytkowników',
        correct: false,
      },
      {
        text: 'przechwycenie tokenu bezpieczeństwa SID przez nieuprawnionego użytkownika',
        correct: false,
      },
      {
        text: 'czasowe przejęcie przez proces (wątek) uprawnień innego podmiotu',
        correct: true,
      },
    ],
  },
  {
    text: '56. Hasła użytkowników systemu Windows są przechowywane:',
    answers: [
      { text: 'w rejestrze systemowym', correct: false },
      { text: 'w bazie SAM na dysku', correct: true },
      {
        text: 'w formie nieodwracalnego wyniku funkcji mieszającej',
        correct: true,
      },
      {
        text: 'w pliku shadow zaszyfrowanym kluczem RSA (SYSKEY), do którego dostęp ma tylko administrator systemu',
        correct: false,
      },
    ],
  },
  {
    text: '57. W poleceniu: iptables -I INPUT -p icmp --icmp-type echo-request -m recent --name "ping" --set nazwa "ping":',
    answers: [
      {
        text: 'jest to komentarz, pozwalający na szybką identyfikację reguły w przyszłości (np. w celu modyfikacji lub skasowania)',
        correct: false,
      },
      {
        text: 'określa ten z ostatnio inicjowanych modułów filtracji (łańcuchów), który teraz będzie przechwytywał wskazane pakiety',
        correct: false,
      },
      {
        text: 'identyfikuje konkretne statystyki, które później można wykorzystać do dalszej selekcji ruchu',
        correct: true,
      },
      {
        text: 'definiuje nazwę pliku, który zawierać będzie informacje o ruchu pakietów do bieżącej reguły zapory',
        correct: false,
      },
    ],
  },
  {
    text: '58. Serwer OpenVPN umożliwia uwierzytelnianie klientów poprzez:',
    answers: [
      { text: 'klucze kryptograficzne', correct: true },
      { text: 'hasła użytkowników', correct: false },
      { text: 'certyfikaty X.509', correct: true },
      { text: 'protokół Kerberos', correct: false },
      {
        text: 'biometrycznie, poprzez analizę długości rzutu beretem',
        correct: false,
      },
    ],
  },
  {
    text: '59. Po uruchomieniu Notatnika na niskim poziomie integralności, może on zapisywać pliki:',
    answers: [
      {
        text: 'tylko w katalogach o przypisanym poziomie integralności co najwyżej niskim, np. %userprofile%/AppData/LocalLow',
        correct: true,
      },
      {
        text: 'tylko w katalogach o przypisanym poziomie integralności co najmniej niskim, np. %userprofile%/Documents',
        correct: false,
      },
      { text: 'nigdzie', correct: false },
      {
        text: 'tylko w katalogu z danymi tymczasowymi, np. %systemroot%/Temp',
        correct: false,
      },
    ],
  },
  {
    text: '60. Wykorzystanie kryptograficznego podpisu wiadomości pozwala odbiorcy zweryfikować:',
    answers: [
      {
        text: 'autentyczność wiadomości przy użyciu klucza prywatnego odbiorcy',
        correct: false,
      },
      {
        text: 'autentyczność wiadomości przy użyciu klucza publicznego nadawcy',
        correct: true,
      },
      {
        text: 'autentyczność wiadomości przy użyciu klucza prywatnego nadawcy',
        correct: false,
      },
      {
        text: 'autentyczność wiadomości przy użyciu klucza publicznego odbiorcy',
        correct: false,
      },
    ],
  },
  {
    text: '61. Wykorzystanie kryptograficznego podpisu wiadomości pozwala odbiorcy zweryfikować:',
    answers: [
      {
        text: 'pochodzenie wiadomości przy użyciu klucza prywatnego odbiorcy',
        correct: false,
      },
      {
        text: 'pochodzenie wiadomości przy użyciu klucza publicznego odbiorcy',
        correct: false,
      },
      {
        text: 'pochodzenie wiadomości przy użyciu klucza prywatnego nadawcy',
        correct: false,
      },
      {
        text: 'pochodzenie wiadomości przy użyciu klucza publicznego nadawcy',
        correct: true,
      },
    ],
  },
  {
    text: '62. Dodanie klucza wygenerowanego dla nowego agenta DRA, do istniejącego wcześniej zaszyfrowanego pliku, można uzyskać:',
    answers: [
      {
        text: 'automatycznie, poprzez otwarcie tego pliku przez nowego agenta DRA',
        correct: false,
      },
      {
        text: 'automatycznie, przy pierwszym otwarciu tego pliku przez dowolnego administratora',
        correct: false,
      },
      {
        text: 'samoczynnie, przy okazji pierwszego dostępu do pliku kogoś mogącego odszyfrować ten plik',
        correct: false,
      },
      { text: 'wydając polecenie cipher /u', correct: true },
    ],
  },
  {
    text: '63. Program SSH można wykorzystać m.in. do:',
    answers: [
      { text: 'stworzenia dynamicznego proxy aplikacyjnego', correct: true },
      {
        text: 'przekierowywania portów zdalnego serwera do maszyny lokalnej (klienta)',
        correct: true,
      },
      {
        text: 'stworzenia proxy www wyłącznie dla protokołu HTTPS',
        correct: false,
      },
      {
        text: 'przekierowywania portów maszyny lokalnej (klienta) do zdalnego serwera',
        correct: true,
      },
    ],
  },
  {
    text: '64. Uprawnienia domyślne na liście POSIX ACL nadawane są:',
    answers: [
      {
        text: 'jedynie plikom wykonywalnym w celu uściślenia jakie uprawnienia mają mieć pliki tworzone w czasie działania tych programów',
        correct: false,
      },
      {
        text: 'jedynie katalogom w celu inicjowania list ACL nowo tworzonym plikom',
        correct: true,
      },
      {
        text: 'plikom i katalogom w celu określenia uprawnień w przypadku braku pasującego wpisu ACE',
        correct: false,
      },
      {
        text: 'plikom i katalogom w celu określenia ACL w przypadku ich kopiowania lub przenoszenia do innego katalogu',
        correct: false,
      },
    ],
  },
  {
    text: '65. Które z poniższych zdarzeń są efektami braku wirtualizacji danego klucza rejestru systemu Windows?',
    answers: [
      {
        text: 'operacja zapisu wartości parametrów tego klucza przez proces nie posiadający uprawnienia zapisu kończy się powodzeniem',
        correct: false,
      },
      {
        text: 'operacja zapisu wartości parametrów tego klucza przez proces posiadający uprawnienie zapisu kończy się błędem',
        correct: false,
      },
      {
        text: 'operacja zapisu wartości parametrów tego klucza przez proces nie posiadający uprawnienia zapisu kończy się powodzeniem',
        correct: false,
      },
      {
        text: 'operacja zapisu wartości parametrów tego klucza przez proces nie posiadający uprawnienia zapisu kończy się błędem',
        correct: true,
      },
    ],
  },
  {
    text: '66. Z jaką inną opcją polityki silnych haseł ma bezpośredni związek ilość haseł pamiętanych w historii?',
    answers: [
      { text: 'maksymalny okres ważności hasła', correct: false },
      { text: 'minimalny okres ważności', correct: true },
      { text: 'minimalna długość hasła', correct: false },
    ],
  },
  {
    text: '67. Jak modyfikowana jest maska uprawnień POSIX ACL przy zmianie uprawnień do danego pliku:',
    answers: [
      {
        text: 'nowa maska jest alternatywą bitową uprawnień nazwanych użytkowników, grupy i nazwanych grup',
        correct: true,
      },
      {
        text: 'nowa maska jest alternatywą bitową starej maski i wszystkich uprawnień nowo nadanych przez setfacl',
        correct: false,
      },
      {
        text: 'nowa maska jest iloczynem logicznym starej maski i wszystkich uprawnień nowo nadanych przez setfacl',
        correct: false,
      },
      {
        text: 'nowa maska jest alternatywą bitową wszystkich uprawnień danego pliku (właściciela, grupy, pozostałych, nazwanych użytkowników, nazwanych grup)',
        correct: false,
      },
    ],
  },
  {
    text: '68. Czyje hasło wymagane jest przy uruchomieniu polecenia sudo?',
    answers: [
      { text: 'zawsze administratora systemu', correct: false },
      {
        text: 'zawsze użytkownika wywołujacego dane polecenie',
        correct: false,
      },
      { text: 'w zależności od ustawień w polityce sudoers', correct: true },
      {
        text: 'zawsze użytkownika z uprawnieniami którego chcemy wykonać dane polecenie',
        correct: false,
      },
    ],
  },
  {
    text: '69. Kolejność sprawdzania reguł polityki przez TCP Wrappera (pomijajac opcje only_from oraz no_access) jest następująca:',
    answers: [
      {
        text: 'najpierw hosts.allow, potem hosts.deny, do odnalezienia pasującej reguły',
        correct: true,
      },
      {
        text: 'sprawdzane są wszystkie reguły i jeżeli żadna z nich nie kończy się DENY, przyznawany jest dostęp',
        correct: false,
      },
      {
        text: 'najpierw hosts.deny, potem hosts.allow, do odnalezienia pierwszej pasującej reguły',
        correct: false,
      },
      {
        text: 'sprawdzane są wszystkie reguły i jeżeli żadna z nich nie kończy się DENY, a chociaż jedna kończy się ALLOW, przyznawany jest dostęp',
        correct: false,
      },
    ],
  },
  {
    text: '70. Ustawienia protokołu ESP w systemie Windows umożliwiają:',
    answers: [
      {
        text: 'przesyłanie niezaszyfrowanego pakietu zabezpieczonego przed modyfikacją przy pomocy kryptograficznych funkcji mieszających',
        correct: true,
      },
      {
        text: 'komunikację w trybie transportowym (bezpośrednim, host-to-host)',
        correct: true,
      },
      { text: 'komunikację w trybie tunelowym (net-to-net)', correct: true },
      {
        text: 'ustanowienie bezpiecznego kanału do zarządzania asocjacją IPsec',
        correct: false,
      },
    ],
  },
  {
    text: '71. Mechanizm iptables może dokonywać wyboru reguł filtracji dla danego pakietu przez:',
    answers: [
      {
        text: 'zasadę pierwszego dopasowania i zawsze przerywa szukanie przy pierwszym dopasowaniu',
        correct: false,
      },
      {
        text: 'zasadę najlepszego dopasowania (najbardziej szczegółowa reguła)',
        correct: false,
      },
      {
        text: 'zasadę pierwszego dopasowania, ale niekoniecznie przerywa szukanie przy pierwszym dopasowaniu',
        correct: true,
      },
      {
        text: 'zasadę określoną w polityce danego łańcucha (np. BESTMATCH, FIRSTMATCH)',
        correct: false,
      },
    ],
  },
  {
    text: '72. Wirtualizacja rejestru w systemie Windows:',
    answers: [
      {
        text: 'chroni konfigurację systemu przed niepożądanymi zmianami',
        correct: true,
      },
      {
        text: 'pozwala aplikacji 32-bitowej na modyfikację obszarów rejestru, do których aplikacja nie ma prawa zapisu',
        correct: false,
      },
      { text: 'dotyczy wszystkich gałęzi rejestru', correct: false },
      {
        text: 'jest mechanizmem koniecznym do uruchomienia wirtualnych systemów Windows',
        correct: false,
      },
    ],
  },
  {
    text: '73. Tunele IPsec:',
    answers: [
      { text: 'stosują protokół TLS do szyfrowania ruchu', correct: false },
      { text: 'stosują protokół AH do szyfrowania ruchu', correct: false },
      { text: 'stosują protokół ESP do szyfrowania ruchu', correct: true },
      {
        text: 'stosują protokół AH do uwierzytelniania stron tunelu',
        correct: false,
      },
    ],
  },
  {
    text: '74. Które z poniższych twierdzeń jest prawdziwe?',
    answers: [
      {
        text: 'program SSH na komputerze A może połączyć się z komputerem B, tak by B nasłuchiwał na połączenia na porcie X. Metoda ta nazywa się local port forwarding (-L)',
        correct: false,
      },
      {
        text: 'program SSH do uwierzytelniania oraz szyfrowania komunikacji pomiędzy komputerem A i B wykorzystuje algorytm RSA',
        correct: false,
      },
      {
        text: 'program SSH na komputerze A wykorzystuje klucz publiczny komputera B w celu weryfikacji czy tożsamość B się nie zmieniła',
        correct: true,
      },
      {
        text: 'program SSH na komputerze A może połączyć się z komputerem B, tak by B nasłuchiwał na połączenia na porcie X. Metoda ta nazywa się remote port forwarding (-R)',
        correct: true,
      },
    ],
  },
  {
    text: '75. Agent DRA w systemie Windows to:',
    answers: [
      {
        text: 'administrator systemu Windows, któremy przypisano prawo tworzenia strumieni ADS',
        correct: false,
      },
      {
        text: 'lokalny administrator stacji roboczej w środowisku domenowym mogący robić kopie zapasowe',
        correct: false,
      },
      { text: 'główny administrator domeny (serwera AD)', correct: false },
      {
        text: 'konto pozwalające na dostęp do plików zaszyfrowanych przez EFS',
        correct: true,
      },
    ],
  },
  {
    text: '76. Które z poniższych twierdzeń dotyczących POSIX ACL są prawdziwe?',
    answers: [
      {
        text: 'w momencie tworzenia katalogu jego uprawnienia ACL kopiowane są z domyślnych uprawnień (Default ACL) folderu nadrzędnego z wykluczeniem uprawnienia do wykonywania',
        correct: false,
      },
      {
        text: 'w momencie tworzenia pliku jego uprawnienia domyślne (Default ACL) zostają odziedziczone z folderu nadrzędnego',
        correct: false,
      },
      {
        text: 'w momencie tworzenia pliku jego uprawnienia ACL kopiowane są z domyślnych uprawnień (Default ACL) folderu nadrzędnego z wykluczeniem uprawnienia do wykonywania',
        correct: true,
      },
      {
        text: 'w momencie tworzenia katalogu jego uprawnienia domyślne (Default ACL) zostają odziedziczone z folderu nadrzędnego',
        correct: true,
      },
    ],
  },
  {
    text: '77. Standard IEEE 802.1ae:',
    answers: [
      {
        text: 'to odpowiednik IPsec na poziomie warstwy transportowej',
        correct: false,
      },
      {
        text: 'oferuje uwierzytelnianie na poziomie warstwy sieciowej OSI',
        correct: false,
      },
      {
        text: 'oferuje ochronę poufności i integralności komunikacji na poziomie warstwy MAC',
        correct: true,
      },
      {
        text: 'oferuje ochronę poufności i integralności komunikacji na poziomie warstwy OSI',
        correct: false,
      },
    ],
  },
  {
    text: '78. Wskaż, które z wymienionych operacji obsługiwane są przez mechanizm POSIX CAP (capabilities):',
    answers: [
      { text: 'administrowanie siecią', correct: true },
      { text: 'administrowanie modułami jądra', correct: true },
      { text: 'omijanie limitów zasobowych', correct: true },
      {
        text: 'omijanie ograniczeń dotyczących kontroli dostępu do plików',
        correct: true,
      },
      {
        text: 'dowiązanie do gniazd numerów portów systemowych',
        correct: true,
      },
      {
        text: 'realizacja komunikacji grupowej rozgłoszeniowej w sieci',
        correct: false,
      },
    ],
  },
  {
    text: '79. Cechą single-sign-on jest:',
    answers: [
      {
        text: 'stosowanie funkcji skrótu w celu uzyskania podpisu cyfrowego',
        correct: false,
      },
      { text: 'jednokrotne uwierzytelnianie użytkownika sieci', correct: true },
      { text: 'podpisywanie każdego pliku innym kluczem', correct: false },
      {
        text: 'szyfrowanie sesji przy pomocy jednorazowego klucza',
        correct: false,
      },
    ],
  },
  {
    text: '80. Który z wymienionych protokołów pozwala w procesie uwierzytelniania całkowicie uniknąć przesyłania hasła podmiotu uwierzytelnianego (w jakiejkolwiek postaci):',
    answers: [
      { text: 'SSH', correct: false },
      { text: 'SSL', correct: false },
      { text: 'CHAP', correct: true },
      { text: 'PAP', correct: false },
      { text: 'SPAP', correct: false },
    ],
  },
  {
    text: '81. Metoda programowego generowania haseł jednorazowych opracowana przez L.Lamporta polega m.in. na:',
    answers: [
      {
        text: 'wygenerowaniu losowe listy N haseł wykorzystywanych wyrywkowo przez system',
        correct: false,
      },
      {
        text: 'wygenerowaniu N-elementowej sekwencji wywierdoznej deterministycznie z zadanego hasła',
        correct: true,
      },
      {
        text: 'wykorzystywaniu silnej kryptografii z kluczem równym początkowemu hasłu do ochrony kolejnych haseł',
        correct: false,
      },
      {
        text: 'wykorzystywaniu wygenerowanych haseł w kolejności odwrotnej (od ostatniego począwszy)',
        correct: true,
      },
    ],
  },
  {
    text: '82. Które narzędzia wykorzystywane są do ochrony antyspamowej w systemie pocztowym?',
    answers: [
      { text: 'open proxy', correct: false },
      { text: 'open relay', correct: false },
      { text: 'szare listy', correct: true },
      { text: 'filtry Bayesa', correct: true },
    ],
  },
  {
    text: '83. Spośród podanych mechanizmów wskaż te wykorzystujące kryptografię:',
    answers: [
      { text: 'X.509', correct: true },
      { text: 'podpis cyfrowy', correct: true },
      { text: 'ROT13', correct: false },
      { text: 'UUencoding', correct: false },
    ],
  },
  {
    text: '84. Wskaż cechy SNAT:',
    answers: [
      { text: 'wymaga utrzymywania listy aktywnych translacji', correct: true },
      { text: 'ukrywa rzeczywisty adres nadawcy pakietu', correct: true },
      {
        text: 'może być pomyślnie wykonane pośrodku tunelu VPN zarówno w trybie tunelowym jak i transportowym',
        correct: false,
      },
      {
        text: 'może być pomyślnie wykonane pośrodku tunelu VPN tylko w trybie transportowym',
        correct: true,
      },
      {
        text: 'wymaga uwierzytelnienia stron przed zestawieniem połączenia',
        correct: false,
      },
      {
        text: 'pozwala uniknąć powtórnego sprawdzania reguł filtracji dla ruchu zweryfikowanego uprzednio',
        correct: false,
      },
      {
        text: 'dokonuje podmiany zarówno adresu jak i numeru portu',
        correct: true,
      },
    ],
  },
  {
    text: '85. Komputery kwantowe i obliczenia kwantowe mogą stanowić poważne zagrożenie dla:',
    answers: [
      { text: 'steganografii', correct: false },
      {
        text: 'aktualnych mechanizmów detekcji anomalii w systemach IDS',
        correct: false,
      },
      {
        text: 'współczesnych algorytmów kryptografii asymetrycznej, takich jak RSA',
        correct: true,
      },
      { text: 'zapór sieciowych typu proxy', correct: false },
    ],
  },
  {
    text: '86. Jak zachowa się system kontroli ACL standardu POSIX w przypadku użytkownika U należącego do grupy G i wpisanego na liście ACL obiektu p, jeśli ani U ani G nie mają jawnie przydzielonego prawa r, ale kategoria "wszyscy użytkownicy" (others) takie uprawnienie do obiektu p posiada:',
    answers: [
      {
        text: 'prawo do obiektu p nie zostanie efektywnie przyznane, ale U odziedziczy je w głąb, jeśli p jest katalogiem',
        correct: false,
      },
      {
        text: 'prawo r do obiektu p zostanie efektywnie przyznane bezwarunkowo',
        correct: false,
      },
      {
        text: 'prawo r do obiektu p zostanie efektywnie przyznane, o ile U jest właścicielem p',
        correct: false,
      },
      {
        text: 'prawo r do obiektu p nie zostanie efektywnie przyznane',
        correct: true,
      },
    ],
  },
  {
    text: '87. Funkcja skrótu SHA-3 różni się od SHA-2:',
    answers: [
      { text: 'ograniczeniami eksportowymi', correct: false },
      { text: 'posiadaniem strumieniowego trybu pracy', correct: false },
      { text: 'odpornością na ataki Length extension', correct: true },
      { text: 'użyciem asymetrycznego schematu szyfrowania', correct: false },
    ],
  },
  {
    text: '88. Wersja 3DES-EDE jest wzmocnieniem algorytmu kryptograficznego DES osiągniętym poprzez:',
    answers: [
      {
        text: 'trzystopniowe sprawdzenie losowości doboru klucza',
        correct: false,
      },
      {
        text: 'trzykrotne użycie algorytmu DES w trybie szyfrowania, deszyfrowania i ponownie szyfrowania',
        correct: true,
      },
      {
        text: 'trzykrotne zastosowanie konwencji jednokierunkowej Electronic Data Exchange',
        correct: false,
      },
      {
        text: 'podział wyniku szyfrowania na 3 porcje różnej długości wg standardu electronic Data Exchange',
        correct: false,
      },
    ],
  },
  {
    text: '89. Własność Perfect Forward Secrecy w przypadku generowania kluczy kryptograficznych:',
    answers: [
      {
        text: 'wymaga stosowania każdego klucza głównego (master) tylko jeden raz',
        correct: false,
      },
      {
        text: 'ogranicza skutki znalezienia klucza sesji jedynie do części komunikacji',
        correct: true,
      },
      {
        text: 'każdy klucz sesji generowany jest z innego klucza głównego (master)',
        correct: false,
      },
      {
        text: 'stosuje różne klucze sesji do szyfrowania komunikacji w przeciwnych kierunkach',
        correct: false,
      },
    ],
  },
  {
    text: '90. Separację środowiska wykonania poprzez wirtualizację (jądra) systemu operacyjnego oferuje:',
    answers: [
      { text: 'Trusted Execution Environment (TEE)', correct: false },
      { text: 'funkcja systemowa chroot()', correct: true },
      { text: 'Address Space Layout Randomization (ASLR)', correct: false },
      { text: 'Windows Virtualization-Based Security (VBS)', correct: false },
    ],
  },
  {
    text: '91. Tryb strumieniowy szyfrowania:',
    answers: [
      {
        text: 'umożliwia szyfrowanie komunikacji asynchronicznej',
        correct: true,
      },
      { text: 'wymaga klucza prywatnego i publicznego', correct: false },
      {
        text: 'polega na szyfrowaniu każdorazowego po jednym znaku',
        correct: true,
      },
      {
        text: 'wykorzystuje wektor inicjujący rejestr szyfrowania',
        correct: false,
      },
    ],
  },
  {
    text: '92. Określ jakie potencjalne zagrożenia dla bezpieczeństwa niesie funkcja CreateRemotethread():',
    answers: [
      {
        text: 'wywołanie zdalnych procedur (RPC) bez kontroli jądra zdalnego systemu operacyjnego',
        correct: false,
      },
      {
        text: 'wykonanie nieautoryzowanych operacji podszywając się pod autoryzowany proces (obejście autoryzacji)',
        correct: true,
      },
      {
        text: 'wstrzyknięcie złośliwego kodu do przestrzeni adresowej innego procesu w systemie operacyjnym',
        correct: true,
      },
      {
        text: 'nie uwierzytelniony dostęp do komunikacji sieciowej poniżej warstwy transportowej',
        correct: false,
      },
    ],
  },
  {
    text: '93. Koncepcja "zamkniętych grup użytkowników" dotyczy odseparowania danych przetwarzanych przez odrębne grupy użytkowników tego samego środowiska sieciowego. Które z poniższych mechanizmów są realizacją tej koncepcji:',
    answers: [
      { text: 'sandbox net jail', correct: true },
      { text: 'Trusted Execution Environment (TEE)', correct: false },
      { text: 'Virtualization-Based Security (VBS)', correct: false },
      { text: 'sieci wirtualne VLAN', correct: true },
    ],
  },
  {
    text: '94. Które z poniższych protokołów służą realizacji kryptograficznych tuneli wirtualnych z ochroną poufności:',
    answers: [
      { text: 'PEM', correct: false },
      { text: 'ESP', correct: true },
      { text: 'TLS', correct: true },
      { text: 'S/MIME', correct: false },
      { text: 'IPsec', correct: true },
      { text: 'SSL', correct: true },
    ],
  },
  {
    text: '95. Wskaż cechy filtracji kontekstowej (SPF) realizowanej przez zapory sieciowe:',
    answers: [
      {
        text: 'pozwala uniknąć niepotrzebnego sprawdzania reguł dla pakietów powracających w ruchu zweryfikowanym w stronę przeciwną',
        correct: true,
      },
      { text: 'zapora utrzymuje listę aktywnych połączeń', correct: true },
      {
        text: 'dopasowuje pakiety do zapamiętanej historii komunikacji',
        correct: true,
      },
      {
        text: 'historia komunikacji nie ma wpływu na decyzje zapory',
        correct: false,
      },
      {
        text: 'pozwala na dynamiczne modyfikacje reguł filtracji',
        correct: false,
      },
    ],
  },
  {
    text: '96. Które stwierdzenie poprawnie opisują protokół IKE w IPsec:',
    answers: [
      { text: 'realizuje uwierzytelnianie stron', correct: true },
      { text: 'realizuje podpis cyfrowy pakietów IP', correct: false },
      { text: 'korzysta z UDP', correct: true },
      { text: 'korzysta z ICMP', correct: false },
      { text: 'realizuje negocjację algorytmów szyfrujących', correct: true },
      {
        text: 'realizuje wymianę kluczy metodą Diffiego-Hellmana',
        correct: true,
      },
    ],
  },
  {
    text: '97. Mechanizm SYN cookies:',
    answers: [
      {
        text: 'odpowiada na wcześniej odebrany pakiet SYN po zadanym czasie oczekiwania',
        correct: false,
      },
      {
        text: 'pozwala przeglądarce na bezpieczną aktualizację ciasteczek',
        correct: false,
      },
      {
        text: 'minimalizuje ilość informacji potrzebnych przeglądarce do uwierzytelniania zdalnego dostępu',
        correct: false,
      },
      {
        text: 'odpowiada na właśnie odebrany pakiet SYN, tylko jeśli spełnia zadane kryteria poprawności',
        correct: false,
      },
      {
        text: 'nie rozpoczyna zestawienia połączenia po odebraniu segmentu SYN',
        correct: true,
      },
      {
        text: 'jest wykorzystywany do przeprowadzania rozproszonego ataku DoS',
        correct: false,
      },
      {
        text: 'ogranicza zasoby przydzielane przez system przy odbiorze żądania nawiązania połączenia',
        correct: true,
      },
      { text: 'identyfikuje połączenie wartością pola ACK', correct: true },
    ],
  },
  {
    text: '98. Firewalking to:',
    answers: [
      {
        text: 'połączenia zapór filtrujących ruch sieciowy z usługami proxy',
        correct: false,
      },
      {
        text: 'technika odkrywania istnienia zapory sieciowej i otwartych na niej portów',
        correct: true,
      },
      {
        text: 'szeregowe połączenia zapór sieciowych typu proxy',
        correct: false,
      },
      {
        text: 'kaskadowe połączenia zapór sieciowych filtrujących pakiety',
        correct: false,
      },
    ],
  },
  {
    text: '99. Które z poniższych podatności mogą potencjalnie pozwolić na wykonanie nieuprawnionego (złośliwego) kodu w aplikacji:',
    answers: [
      { text: 'remapowanie adresu 0 (dereferencja)', correct: true },
      {
        text: 'randomizacja przydziału przestrzeni adresowej procesu',
        correct: false,
      },
      { text: 'przepełnienie bufora', correct: true },
      { text: 'nadpisanie adresu obsługi przerwania/wyjątku', correct: true },
    ],
  },
  {
    text: '100. Ataki o nazwie phishing:',
    answers: [
      {
        text: 'dotyczą wykradzenia zaufanych certyfikatów użytkownika',
        correct: false,
      },
      {
        text: 'pozwalają w efekcie podszyć się pod atakowanego',
        correct: true,
      },
      {
        text: 'mogą być w pewnym stopniu udaremnianie przy pomocy "czarnych list"',
        correct: true,
      },
      { text: 'zmierzają do fałszowania ciasteczek www', correct: false },
    ],
  },
  {
    text: '101. Mechanizm umożliwiający przydzielenie poszczególnych uprawnień administracyjnych (uprzywilejowanych operacji jądra systemy operacyjnego) użytkownikom to:',
    answers: [
      { text: 'capabilities', correct: true },
      { text: 'sandbox', correct: false },
      { text: 'remote administration', correct: false },
      { text: 'switch root', correct: false },
    ],
  },
  {
    text: '102. Jakie restrykcje wprowadza flaga Secure w definicji ciasteczka WWW?',
    answers: [
      {
        text: 'do ciasteczka nie można uzyskać dostępu w skryptach',
        correct: false,
      },
      {
        text: 'dostęp do ciasteczka ma tylko oryginalna strona, która utworzyła ciasteczko',
        correct: false,
      },
      {
        text: 'ciasteczko będzie wysyłane do serwera tylko w tunelach kryptograficznych',
        correct: true,
      },
      {
        text: 'ciasteczko musiało zostać sprawdzone przez filtr SOP',
        correct: false,
      },
    ],
  },
  {
    text: '103. Użycie IPsec + IKE wprost chroni przed atakiem:',
    answers: [
      { text: 'name spoofing', correct: false },
      { text: 'ARP cache spoofing', correct: false },
      { text: 'TCP spoofing', correct: true },
      { text: 'session hijacking', correct: true },
      { text: 'network sniffing', correct: true },
      { text: 'ARP spoofing', correct: false },
    ],
  },
  {
    text: '104. Mechanizm single-sign-on cechuje:',
    answers: [
      {
        text: 'uwierzytelnianie użytkownika wobec wielu serwerów jednorazową procedurą',
        correct: true,
      },
      {
        text: 'podpisywanie każdego pakietu danych VPN innym kluczem',
        correct: false,
      },
      {
        text: 'uwierzytelnianie użytkownika za każdym razem innym hasłem',
        correct: false,
      },
      {
        text: 'uwierzytelnianie użytkownika innym hasłem wobec każdego serwera',
        correct: false,
      },
      { text: 'autoryzacja podmiotu zgodnie z modelem MAC', correct: false },
      {
        text: 'uwierzytelnianie podmiotu za każdym razem innych hasłem jednorazowym',
        correct: false,
      },
      {
        text: 'zastosowanie mechanizmu szyfrowania asymetrycznego w procesie autoryzacji',
        correct: false,
      },
      {
        text: 'zastosowanie pojedynczego uwierzytelniania podmiotu w dostępie do wielu różnych zasobów',
        correct: true,
      },
    ],
  },
  {
    text: '105. Proszę wskazać algorytmy podpisu cyfrowego:',
    answers: [
      { text: 'ElGamal', correct: true },
      { text: 'Blowfish', correct: false },
      { text: 'Rijndael', correct: false },
      { text: 'SHA-1', correct: false },
      { text: 'MD5', correct: false },
      { text: 'żadne z powyższych', correct: false },
    ],
  },
  {
    text: '106. Wskaż prawidłowe stwierdzenia dotyczące metod uwierzytelniania systemów operacyjnych MS Windows w środowisku sieciowym:',
    answers: [
      { text: 'NTLM jest bezpieczniejszy niż LM', correct: true },
      { text: 'Kerberos jest bezpieczniejszy niż LM', correct: true },
      {
        text: 'Kerberos jest dostępny tylko w środowisku domenowym',
        correct: true,
      },
      { text: 'LM jest bezpieczniejszy niż NTLM', correct: false },
    ],
  },
  {
    text: '107. Wskaż własności protokołu RADIUS:',
    answers: [
      {
        text: 'zabezpiecza pocztę elektroniczną wraz z załącznikami',
        correct: false,
      },
      { text: 'mogą go wykorzystywać np. serwery dostępowe', correct: true },
      { text: 'jest realizacją koncepcji AAA', correct: true },
      {
        text: 'pozwala na centralizację zarządzania danymi, które dystrybuuje',
        correct: false,
      },
      { text: 'wspomaga uwierzytelnianie', correct: true },
      { text: 'pracuje w architekturze klient-serwer', correct: true },
    ],
  },
  {
    text: '108. Następująca reguła filtracji zapory sieciowej: od *.*.*.* -> do 1.1.1.1, port źródłowy *, port docelowy 80, protokół TCP, flagi ACK=0, reakcja odrzuć:',
    answers: [
      {
        text: 'blokuje wszelkie połączenia nawiązywane z serwera www o dowolnym adresie',
        correct: false,
      },
      {
        text: 'blokuje wszelkie połączenia nawiązywane z serwera www o adresie 1.1.1.1',
        correct: true,
      },
      {
        text: 'blokuje wszelkie połączenia nawiązywane z serwerem www o adresie 1.1.1.1',
        correct: false,
      },
      {
        text: 'blokuje wszelkie połączenia nawiązywane z serwerem www o dowolnym adresie',
        correct: false,
      },
    ],
  },
  {
    text: '109. Które z poniższych protokołów służą realizacji kryptograficznych tuneli wirtualnych z ochroną poufności?',
    answers: [
      { text: 'PGP', correct: false },
      { text: 'ESP', correct: true },
      { text: 'X.400', correct: false },
      { text: 'AH', correct: false },
    ],
  },
  {
    text: '110. Wskaż protokoły wymagające zabezpieczenia autentyczności i integralności danych, ale niekoniecznie poufności:',
    answers: [
      { text: 'DNS (Domain Name Service)', correct: true },
      { text: 'ARP (Address Resolution Protocol)', correct: true },
      { text: 'STP (Spanning Tree Protocol)', correct: true },
      { text: 'rlogin (Remote Login)', correct: false },
    ],
  },
  {
    text: '111. Które nazwy ataków dotyczą zalewania użytkowników niepożądaną informacją:',
    answers: [
      { text: 'spam', correct: true },
      { text: 'pharming', correct: false },
      { text: 'scam', correct: false },
      { text: 'spim', correct: true },
    ],
  },
  {
    text: '112. Do szyfrów asymetrycznych zaliczamy:',
    answers: [
      { text: 'SHA', correct: false },
      { text: 'SSH', correct: false },
      { text: 'AES', correct: false },
      { text: 'żadne z powyższych', correct: true },
    ],
  },
  {
    text: '113. W metodzie uzgadniania klucza Diffiego-Hellmana system może zostać skompromitowany poprzez:',
    answers: [
      { text: 'przechwycenie jednego z wymienianych kluczy', correct: false },
      { text: 'przechwycenie obu wymienianych kluczy', correct: false },
      {
        text: 'postawienie fałszywego klucza w miejsce każdego z wymienianych',
        correct: true,
      },
      {
        text: 'postawienie fałszywego klucza w miejsce dowolnego z wymienianych',
        correct: false,
      },
    ],
  },
  {
    text: '114. Algorytm SHA-256 i SHA-512 różnią się wzajemnie:',
    answers: [
      { text: 'odpornością na ataki Length extension', correct: false },
      { text: 'podatnością na kolizje', correct: false },
      { text: 'wielkością wynikowego skrótu', correct: true },
      { text: 'żadne z powyższych', correct: false },
    ],
  },
  {
    text: '115. Wskaż cechy zapory sieciowej zrealizowanej poprzez Komputer-Twierdzę (Bastion Host):',
    answers: [
      {
        text: 'dla ruchu z zewnątrz zapora "przykrywa" sobą całą sieć wewnętrzną',
        correct: true,
      },
      {
        text: 'dla ruchu od wewnątrz zapora "przykrywa" sobą cały świat zewnętrzny',
        correct: true,
      },
      { text: 'w zaporze nie jest realizowany routing', correct: true },
      {
        text: 'komunikacja zachodzi wyłącznie przez usługi proxy',
        correct: true,
      },
    ],
  },
  {
    text: '116. Funkcja systemowa chroot():',
    answers: [
      { text: 'oferuje kontrolę nad komunikacją sieciową', correct: false },
      { text: 'nie oferuje kontroli nad komunikacją sieciową', correct: true },
      {
        text: 'jest wykorzystywana przez narzędzie sudo do zmiany aktualnych uprawnień procesu',
        correct: false,
      },
      {
        text: 'służy do chwilowego przeniesienia administratora na wybranego użytkownika',
        correct: false,
      },
      { text: 'ogranicza aplikacji dostęp do systemu plików', correct: true },
      { text: 'chroni system przed atakami DoS', correct: false },
      {
        text: 'jest jednym z mechanizmów tworzenia piaskownicy',
        correct: true,
      },
      {
        text: 'pozwala wykonać pojedyncze polecenia administracyjne bez weryfikacji hasła',
        correct: false,
      },
      {
        text: 'wymaga powielania plików niezbędnych dla poprawnego działania aplikacji',
        correct: true,
      },
      {
        text: 'pozwala wielokrotnie skorzystać z uprawnień administratora bez weryfikacji hasła przez ustalony czas',
        correct: false,
      },
      { text: 'ogranicza procesom dostępność systemu plików', correct: true },
    ],
  },
  {
    text: '117. Które z poniższych technologii sprzętowych umożliwiają separację środowiska wykonawczego aplikacji poprzez wirtualizację całości bądź części systemu operacyjnego (np. jądra systemu):',
    answers: [
      { text: 'TEE (Trusted Execution Environment)', correct: true },
      { text: 'VBS (Virtualization-Based Security)', correct: true },
      { text: 'ARM TrustZone', correct: true },
      { text: 'SSL (Secure Socket Layer)', correct: false },
    ],
  },
  {
    text: '118. Który z wymienionych protokołów chroni klienta przed przypadkiem podszywania się pod zaufany serwer?',
    answers: [
      { text: 'IPsec + PSK(Pre shared key)', correct: false },
      { text: 'HTTP/1.1', correct: false },
      { text: 'SSH', correct: true },
      { text: 'HTTP/1.0', correct: false },
    ],
  },
  {
    text: '119. Który angielski termin określa wykorzystanie do ataku znanych luk w systemie atakowanym:',
    answers: [
      { text: 'exploiting', correct: true },
      { text: 'eavesdropping', correct: false },
      { text: 'masquerading', correct: false },
      { text: 'tampering', correct: false },
    ],
  },
  {
    text: '120. Metoda Diffiego-Hellmana:',
    answers: [
      { text: 'generuje programowo hasła SSO', correct: false },
      {
        text: 'realizuje uwierzytelnianie metodą haseł jednorazowych',
        correct: false,
      },
      {
        text: 'wykorzystuje ideę asymetrycznej pary kluczy (prywatny – publiczny)',
        correct: false,
      },
      { text: 'pozwala wygenerować symetryczny klucz sesji', correct: true },
    ],
  },
  {
    text: '121. Które ataki sieciowe można wyeliminować stosując ochronę autentyczności komunikacji?',
    answers: [
      { text: 'ARP cache poisoning', correct: false },
      { text: 'DNS cache poisoning', correct: false },
      { text: 'ARP spoofing', correct: false },
      { text: 'DNS spoofing', correct: true },
    ],
  },
  {
    text: '122. Wskaż cechy PKI:',
    answers: [
      {
        text: 'certyfikaty kluczy prywatnych są składowane w repozytoriach takich jak np. DNSsec',
        correct: false,
      },
      {
        text: 'certyfikaty kluczy są wzajemnie wystawiane przez innych użytkowników',
        correct: false,
      },
      {
        text: 'unieważnienia certyfikatu klucza ma również postać certyfikatu',
        correct: true,
      },
      {
        text: 'do zweryfikowania certyfikatu klucza publicznego użytkownika potrzebny jest certyfikat głównego urzędu (RootCA)',
        correct: true,
      },
    ],
  },
  {
    text: '123. Atak typu TCP spoofing wymaga:',
    answers: [
      { text: 'intensywnego zalewania segmentami SYN', correct: false },
      {
        text: 'odgadnięcia numeru ISN strony odbierającej żądanie nawiązania połączenia',
        correct: true,
      },
      {
        text: 'odgadnięcia numeru sekwencyjnego pierwszego segmentu strony żądającej nawiązania połączenia',
        correct: false,
      },
      {
        text: 'zalewania żądaniami nawiązania połączenia TCP w trybie rozgłoszeniowym',
        correct: false,
      },
    ],
  },
  {
    text: '124. W protokole HTTP/2:',
    answers: [
      { text: 'uwierzytelnianie klienta jest obowiązkowe', correct: false },
      { text: 'uwierzytelnianie serwera jest opcjonalne', correct: true },
      { text: 'uwierzytelnianie serwera jest obowiązkowe', correct: false },
      {
        text: 'szyfrowanie całej komunikacji jest obowiązkowe',
        correct: false,
      },
    ],
  },
  {
    text: '125. Które z poniższych protokołów służą realizacji kryptograficznych tuneli wirtualnych z ochroną integralności?',
    answers: [
      { text: 'TLS', correct: true },
      { text: 'S/MIME', correct: false },
      { text: 'AH', correct: true },
      { text: 'ESP', correct: true },
    ],
  },
  {
    text: '126. Standard IEEE 802.1X:',
    answers: [
      {
        text: 'pozwala na wykorzystanie certyfikatów X.509 do realizacji swoich zadań',
        correct: true,
      },
      {
        text: 'pozwala uwierzytelniać stanowiska sieciowe przy dostępie do sieci lokalnej',
        correct: true,
      },
      {
        text: 'oferuje wymianę kluczy w sieci WiFi przy wykorzystaniu zarówno haseł jak i certyfikatów',
        correct: true,
      },
      {
        text: 'umożliwia scentralizowane uwierzytelnianie wielu punktów zdalnego dostępu',
        correct: true,
      },
      {
        text: 'podnosi dostępność poprzez redundantne rozproszenie danych uwierzytelniających do wielu punktów dostępowych',
        correct: false,
      },
    ],
  },
  {
    text: '127. Wskaż rodzaje adresów, które zapora sieciowa dokonująca translacji NAT powinna filtrować w pakietach przychodzących od strony zewnętrznej sieci publicznej:',
    answers: [
      { text: 'dowolne prywatne IP, w polu źródłowym', correct: true },
      { text: 'dowolne prywatne IP, w polu docelowym', correct: false },
      {
        text: 'adresy wykorzystywane wewnątrz, w polu źródłowym',
        correct: true,
      },
      {
        text: 'adresy wykorzystywane wewnątrz, w polu docelowym',
        correct: false,
      },
    ],
  },
  {
    text: '128. Do przechowywania danych uwierzytelniających w systemie MS Windows aplikacje mogą skorzystać z:',
    answers: [
      { text: 'Winlog API', correct: false },
      { text: 'Data Protection API (DPAPI)', correct: true },
      { text: 'Credential Manager API', correct: true },
      { text: 'Generic Security Service API (GSSAPI)', correct: false },
    ],
  },
  {
    text: '129. Następująca reguła filtracji zapory sieciowej: od *.*.*.* -> do 1.1.1.1, port źródłowy *, port docelowy 80, protokół TCP, flagi SYN=1, reakcja odrzuć:',
    answers: [
      {
        text: 'blokuje wszelkie połączenia nawiązywane z serwera www o dowolnym adresie',
        correct: false,
      },
      {
        text: 'blokuje wszelkie połączenia nawiązywane z serwerem www o dowolnym adresie',
        correct: false,
      },
      {
        text: 'blokuje wszelkie połączenia nawiązywane z serwerem www o adresie 1.1.1.1',
        correct: true,
      },
      {
        text: 'blokuje wszelkie połączenia nawiązywane z serwera www o adresie 1.1.1.1',
        correct: false,
      },
    ],
  },
  {
    text: '130. Które operacje mogą być wykorzystywane do realizacji ataku DoS (Denial of Service):',
    answers: [
      {
        text: 'intensywny strumień segmentów FIN z adresem docelowym ofiary',
        correct: false,
      },
      {
        text: 'fragmentacja datagramu o sumarycznej wielkości ponad 64kB',
        correct: true,
      },
      {
        text: 'intensywny strumień pakietów UDP echo z adresem docelowym ofiary',
        correct: true,
      },
      {
        text: 'intensywny strumień rozgłoszeniowym segmentów SYN z adresem źródłowym ofiary',
        correct: false,
      },
      {
        text: 'intensywny strumień segmentów SYN z adresem docelowym ofiary',
        correct: true,
      },
      {
        text: 'intensywny strumień rozgłoszeniowych pakietów ICMP echo z adresem źródłowym ofiary',
        correct: true,
      },
      {
        text: 'fragmentacja datagramu o sumarycznej wielkości ponad 16 kB',
        correct: false,
      },
    ],
  },
  {
    text: '131. Elementem ochrony przed złośliwym wykorzystaniem przepełnienia bufora może być:',
    answers: [
      { text: 'remapowanie adresu 0 (dereferencja stała)', correct: false },
      {
        text: 'randomizacja przydziału przestrzeni adresowej procesu',
        correct: true,
      },
      {
        text: 'remapowanie adresu obsługi przerwania/wyjątku (dereferencja zmienna)',
        correct: false,
      },
      {
        text: 'wstawienie "kanarka" bezpośrednio po wskaźniku poprzedniej ramki',
        correct: true,
      },
    ],
  },
  {
    text: '132. Wskaż cechy DNAT:',
    answers: [
      {
        text: 'pozwala uniknąć powtórnego sprawdzania reguł filtracji dla ruchu zweryfikowanego uprzednio',
        correct: false,
      },
      { text: 'ukrywa rzeczywisty adres odbiorcy pakietu', correct: true },
      {
        text: 'może być pomyślnie wykonanie pośrodku tunelu VPN tylko w trybie transportowym//tunelowym',
        correct: true,
      },
      { text: 'ukrywa rzeczywisty adres nadawcy pakietu', correct: false },
    ],
  },
  {
    text: '133. Wskaż cechy filtracji bezstanowej realizowanej przez zapory sieciowe:',
    answers: [
      { text: 'zapora utrzymuje listę aktywnych połączeń', correct: false },
      {
        text: 'pozwala uniknąć niepotrzebnego sprawdzania reguł dla pakietów powracających w ruchu zweryfikowanym w stronę przeciwną',
        correct: false,
      },
      {
        text: 'dopasowuje pakiety do zapamiętanej historii komunikacji',
        correct: false,
      },
      {
        text: 'historia komunikacja nie ma wpływu na decyzje zapory',
        correct: true,
      },
      { text: 'wymaga sprawdzania reguł dla każdego pakietu', correct: true },
    ],
  },
  {
    text: '134. Jakie metody uwierzytelniania oferuje protokół HTTP?',
    answers: [
      {
        text: 'obustronne uwierzytelnianie metodą Diffiego-Hellmana',
        correct: false,
      },
      {
        text: 'uwierzytelnianie serwera poprzez certyfikat X.509',
        correct: true,
      },
      {
        text: 'uwierzytelnianie klienta poprzez username token (username + password)',
        correct: true,
      },
      {
        text: 'uwierzytelnianie klienta metodą digest (z użyciem funkcji skrótu)',
        correct: true,
      },
    ],
  },
  {
    text: '135. Wskaż funkcje biblioteczne odpowiedzialne za podatność na atak przepełnienia bufora:',
    answers: [
      { text: 'strcpy()', correct: true },
      { text: 'strncpy()', correct: false },
      { text: 'execv()', correct: false },
      { text: 'shellcode()', correct: false },
      { text: 'gets()', correct: true },
    ],
  },
  {
    text: '136. Niezaprzeczalność to własność potwierdzająca iż:',
    answers: [
      {
        text: 'odbiorca wiadomości nie sfałszował jej treści po odebraniu',
        correct: false,
      },
      {
        text: 'nadawca wiadomości jest rzeczywiście tym za kogo się podaje',
        correct: false,
      },
      { text: 'nadawca wiadomości faktycznie ją wysłał', correct: true },
      { text: 'doszło do ataku aktywnego MiM', correct: false },
      { text: 'odbiorca wiadomości faktycznie ją odebrał', correct: false },
    ],
  },
  {
    text: '137. Termin two-factor authentication (2FA) dotyczy:',
    answers: [
      {
        text: 'procesu potwierdzania tożsamości przy użyciu dwóch oddzielnych procedur lub składników sprzętowych',
        correct: true,
      },
      {
        text: 'użycia w protokole HTTP/2 obustronnego uwierzytelniania',
        correct: false,
      },
      {
        text: 'wykorzystania do kontroli integralności danych algorytmów kryptografii asymetrycznej bazujących na złożoności rozkładu dużych liczb na czynniki (faktoryzacji)',
        correct: false,
      },
      { text: 'uwierzytelniania metodą zawołanie-odzew', correct: false },
    ],
  },
  {
    text: '138. Wskaż cechy poprawnie opisujące DNSsec:',
    answers: [
      {
        text: 'umożliwia przechowywanie kluczy publicznych podmiotów z domeny',
        correct: true,
      },
      {
        text: 'stosuje kryptografię asymetryczną do podpisywania rekordów',
        correct: true,
      },
      {
        text: 'przesyła zapytania i odpowiedzi w tunelu IPsec',
        correct: false,
      },
      {
        text: 'stosuje kryptografię symetryczna do szyfrowania rekordów',
        correct: false,
      },
    ],
  },
  {
    text: '139. Klucze w szyfrowaniu symetrycznym:',
    answers: [
      {
        text: 'mogą być publicznie dostępne pod warunkiem certyfikacji',
        correct: false,
      },
      {
        text: 'zapewniają autentyczność i niezaprzeczalność pod warunkiem zachowania tajności klucza',
        correct: false,
      },
      {
        text: 'zawsze powinny być znane tylko komunikującym się stronom',
        correct: true,
      },
      {
        text: 'wymagają losowego wyboru dużych liczb pierwszych',
        correct: false,
      },
    ],
  },
  {
    text: '140. Które z poniższych protokołów służą realizacji kryptograficznych tuneli wirtualnych:',
    answers: [
      { text: 'TLS', correct: true },
      { text: 'LDAP', correct: false },
      { text: 'X.400', correct: false },
      { text: 'L2TP', correct: true },
      { text: 'IPsec', correct: true },
      { text: 'SSL', correct: true },
    ],
  },
  {
    text: '141. Mechanizm ochrony antyspamowej o nazwie "szare listy" opera się na:',
    answers: [
      {
        text: 'automatycznym weryfikowaniu listy zabronionych adresów nadawców przez MTA',
        correct: false,
      },
      {
        text: 'odesłaniu komunikatu SMTP o czasowej niedostępności usługi',
        correct: true,
      },
      {
        text: 'analizie heurystycznej nagłówka SMTP przez MUA',
        correct: false,
      },
      {
        text: 'dynamicznym weryfikowaniu listy podejrzanych adresów nadawców przez użytkownika',
        correct: false,
      },
    ],
  },
  {
    text: '142. Wskaż zagrożenie bezpieczeństwa związane z fragmentacją datagramów w protokole IP?',
    answers: [
      {
        text: 'scalanie fragmentów perfidnie przygotowanych może powodować nieprzewidziane efekty',
        correct: true,
      },
      { text: 'fragmentacja uniemożliwia stosowanie AH IPsec', correct: false },
      {
        text: 'fragmentacja uniemożliwia stosowanie ESP IPsec',
        correct: false,
      },
      {
        text: 'fragmentacja utrudnia skuteczną filtrację pakietów',
        correct: true,
      },
    ],
  },
  {
    text: '143. Atak na usługę www realizowany poprzez wymuszenie wykonania w przeglądarce kodu pochodzącego z lokalizacji innej niż pobrana strona to:',
    answers: [
      { text: 'same origin forgery', correct: false },
      { text: 'command injection', correct: false },
      { text: 'SQL injection', correct: false },
      { text: 'cross site scripting', correct: true },
    ],
  },
  {
    text: '144. Wskaż który z poniższych standard bezpieczeństwa, którego należy najbardziej unikać w zabezpieczaniu sieci WiFi:',
    answers: [
      { text: 'WEP', correct: true },
      { text: 'WPA2', correct: false },
      { text: 'WPA', correct: false },
      { text: '802.11i', correct: false },
    ],
  },
  {
    text: '145. Wskaż które z poniższych technik mogą być wykorzystywane do tzw. wzmacniania DDoS:',
    answers: [
      { text: 'SYN cookies', correct: false },
      { text: 'protokół DNSsec', correct: false },
      { text: 'rozgłoszenie', correct: true },
      { text: 'protokół DNS', correct: true },
    ],
  },
  {
    text: '146. Która z poniższych cech poprawnie opisuje mechanizm SYN cookies:',
    answers: [
      { text: 'chroni przed atakami buffer overflow', correct: false },
      { text: 'jest jedną z technik wzmacniania ataków DDos', correct: false },
      { text: 'chroni przed atakami SYN flood', correct: true },
      {
        text: 'po wysłaniu segmentu SYN/ACK nadawca zapomina o połączeniu',
        correct: true,
      },
    ],
  },
  {
    text: '147. Mechanizm ACL:',
    answers: [
      { text: 'oferuje niezaprzeczalność nadania wiadomości', correct: false },
      { text: 'jest narzędziem kontroli dostępu do zasobów', correct: true },
      { text: 'oferuje niezaprzeczalność odbioru wiadomości', correct: false },
      { text: 'wyróżnia systemy MAC od DAC', correct: false },
    ],
  },
  {
    text: '148. Wskaż cechy ścisłej kontroli dostępu (MAC):',
    answers: [
      {
        text: 'podatna na błędy samodzielnej konfiguracji przez użytkownika',
        correct: false,
      },
      {
        text: 'wymaga kosztownej globalnej konfiguracji systemu',
        correct: true,
      },
      {
        text: 'nie pozwala użytkownikowi sterować uprawnieniami do jego własnych zasobów',
        correct: true,
      },
      { text: 'trudna do nadzorowania przez system', correct: false },
    ],
  },
  {
    text: '149. Jaki rodzaj filtracji umożliwia podejmowanie decyzji o filtracji pakietów z uwzględnieniem stanu sesji do której przynależą?',
    answers: [
      { text: 'filtry bezstanowe', correct: false },
      { text: 'filtry statyczne', correct: false },
      { text: 'filtry kontekstowe', correct: false },
      { text: 'Stateful Packet Filtering', correct: true },
    ],
  },
  {
    text: '150. Które z poniższych cech poprawnie opisują standard IEEE 802.1X:',
    answers: [
      {
        text: 'umożliwia scentralizowane zarządzanie kluczami publicznymi użytkowników PKI/X',
        correct: false,
      },
      {
        text: 'może wykorzystywać certyfikaty X.509 do kontroli dostępu w sieciach WiFi',
        correct: true,
      },
      { text: 'chroni przed atakami IP spoofing', correct: false },
      { text: 'umożliwia uwierzytelnianie stanowisk sieci LAN', correct: true },
    ],
  },
  {
    text: '151. Algorytm 3DES to:',
    answers: [
      {
        text: 'zastosowanie skrótu qubicznego Extended Signature',
        correct: false,
      },
      { text: 'pseudolosowy generator 3D cube', correct: false },
      { text: 'trzykrotne użycie algorytmu DES', correct: true },
      {
        text: 'podział szyfrogramu na 3 porcje różnej długości wg Disturb-Extraction Split',
        correct: false,
      },
    ],
  },
  {
    text: '152. Która z poniższych cech poprawnie opisuje protokół RADIUS:',
    answers: [
      {
        text: 'wspiera realizację kontroli dostępu do zasobów sieciowych',
        correct: true,
      },
      {
        text: 'umożliwia rejestrowanie dostępu do zasobów sieciowych',
        correct: true,
      },
      { text: 'chroni przed atakami DNS spoofing', correct: false },
      {
        text: 'umożliwia scentralizowane uwierzytelnianie podmiotów',
        correct: true,
      },
      {
        text: 'oferuje wymiane kluczy protokołu IPsec przy wykorzystaniu zarówno haseł jak i certyfikatów PKI',
        correct: false,
      },
      {
        text: 'podnosi dostępność poprzez redundantne rozproszenie danych uwierzytelniających do wielu punktów dostępowych',
        correct: false,
      },
      {
        text: 'udostępnia informacje niezbędne do kontroli uprawnień zdalnego dostępu (np. restrykcje czasowe)',
        correct: true,
      },
      {
        text: 'pozwala na scentralizowane przechowywanie danych uwierzytelniających dla wielu punktów dostępowych',
        correct: true,
      },
    ],
  },
  {
    text: '153. Które określenie poprawnie opisuje protokół IKE?',
    answers: [
      { text: 'oferuje uwierzytelnianie stron', correct: true },
      { text: 'korzysta z ICMP', correct: false },
      { text: 'korzysta z UDP', correct: true },
      { text: 'oferuje negocjację algorytmów szyfrujących', correct: true },
    ],
  },
  {
    text: '154. Przed którymi atakami chroni poprawnie nawiązana sesja VPN (IPsec lub TLS):',
    answers: [
      { text: 'TCP spoofing', correct: true },
      { text: 'SQLi', correct: false },
      { text: 'DNS spoofing', correct: false },
      { text: 'ARP spoofing', correct: false },
    ],
  },
  {
    text: '155. Do zrealizowania zamaskowanego kanału komunikacyjnego może potencjalnie posłużyć:',
    answers: [
      {
        text: 'metoda challenge-response na poziomie warstwy 2 OSI',
        correct: false,
      },
      { text: 'port szeregowy', correct: false },
      { text: 'obciążenie systemu', correct: true },
      { text: 'kolejka wydruku', correct: true },
    ],
  },
  {
    text: '156. Wskaż kto może rozszyfrować plik zaszyfrowany mechanizmem EFS:',
    answers: [
      {
        text: 'każdy agent DRA istniejący w momencie deszyfrowania pliku',
        correct: false,
      },
      { text: 'właściciel pliku', correct: true },
      { text: 'administrator', correct: false },
      {
        text: 'każdy DRA istniejący w momencie szyfrowania pliku',
        correct: true,
      },
    ],
  },
  {
    text: '157. Mechanizm Lock-and-Key:',
    answers: [
      {
        text: 'wymaga uwierzytelnienia użytkownika, np. za pomocą RADIUS-a',
        correct: false,
      },
      {
        text: 'automatycznie blokuje stacje niespełniające wymagań polityki bezpieczeństwa',
        correct: false,
      },
      {
        text: 'może być wykorzystywany do tymczasowego uzyskania uprzywilejowanego dostępu do sieci wewnętrznej z zewnątrz',
        correct: true,
      },
      {
        text: 'służy do translacji reguł filtracji z jednej zapory na inną',
        correct: false,
      },
    ],
  },
  {
    text: '158. Protokół SSL/TLS oferuje:',
    answers: [
      {
        text: 'uwierzytelnianie obustronne uczestników komunikacji',
        correct: true,
      },
      {
        text: 'szyfrowanie transmisji na poziomie warstwy sesji OSI',
        correct: true,
      },
      { text: 'uwierzytelnianie SSO', correct: false },
      {
        text: 'szyfrowanie transmisji na poziomie warstwy transportowej OSI',
        correct: false,
      },
    ],
  },
  {
    text: '159. Wyobraźmy sobie serwer udostępniający wybranym podsieciom dwie usługi: www i ftp. Zapewnienie kontroli dostępu, np. za pomocą narzędzia personal firewall (lub wrappera połączeń) tylko do jednej z tych usług stanowi:',
    answers: [
      {
        text: 'realizację predykatu ograniczonej kontroli dostępu (MAC)',
        correct: false,
      },
      {
        text: 'naruszenie warunku spójności pionowej zabezpieczeń',
        correct: false,
      },
      {
        text: 'naruszenie warunku spójności poziomej zabezpieczeń',
        correct: true,
      },
      { text: 'naruszenie zasad poziomu B1/TCSEC i EAL4/CC', correct: false },
    ],
  },
  {
    text: '160. Który termin określa ochronę informacji przed nieautoryzowanym jej zmodyfikowaniem:',
    answers: [
      { text: 'autoryzacja', correct: false },
      { text: 'niezaprzeczalność', correct: false },
      { text: 'spójność', correct: false },
      { text: 'integralność', correct: true },
    ],
  },
  {
    text: '161. Które z poniższych określeń opisują mechanizm CAP (capabilities):',
    answers: [
      {
        text: 'opisuje prawa uwierzytelnionego użytkownika w bilecie systemu Kerberos',
        correct: false,
      },
      {
        text: 'specyfikuje w certyfikacie klucza publicznego możliwości wykorzystania danego klucza',
        correct: false,
      },
      {
        text: 'pozwala na rozdzielenie uprawnień ogólno administracyjnych na szczegółowe podzbiory',
        correct: true,
      },
      {
        text: 'przydziela użytkownikowi pewne informacje uwierzytelniające przedstawiane następnie podczas dostępu do poszczególnych usług',
        correct: false,
      },
    ],
  },
  {
    text: '162. Którego typu ataku dotyczy następujący opis: Atak ten przeprowadza osoba, która wobec każdej z dwóch uprawnionych stron komunikacji podszywa się za przeciwna strone, pośrednicząc w przesyłaniu danych:',
    answers: [
      { text: 'aktywny', correct: true },
      { text: 'zdalny', correct: false },
      { text: 'pasywny', correct: false },
      { text: 'lokalny', correct: false },
    ],
  },
  {
    text: '163. Co zapewnia uwierzytelnianie przez posiadanie?',
    answers: [
      { text: 'poufność', correct: false },
      { text: 'integralność poufność i integralność', correct: false },
      { text: 'integralność', correct: false },
      { text: 'żadne z powyższych', correct: true },
    ],
  },
  {
    text: '164. Bezpośrednim celem ataku metodą przepełnienia bufora jest:',
    answers: [
      {
        text: 'wypchnięcie wartości zmiennych globalnych programu poza chroniony segment danych',
        correct: false,
      },
      {
        text: 'uszkodzenie zawartości segmentu danych i w efekcie zawieszenie procesu',
        correct: false,
      },
      {
        text: 'uszkodzenie zawartości segmentu kodu i w efekcie zawieszenie procesu',
        correct: false,
      },
      { text: 'nadpisanie adresu powrotu na stosie', correct: true },
    ],
  },
  {
    text: '165. Mechanizm haseł jednorazowych można zrealizować poprzez:',
    answers: [
      { text: 'listy haseł jednorazowych', correct: true },
      { text: 'generowanie hasła jednorazowego co stały czas', correct: true },
      {
        text: 'generowanie hasła jednorazowego w odpowiedzi na żądany kod',
        correct: true,
      },
      {
        text: 'generowanie hasła jednorazowego na podstawie czasu i kodu',
        correct: true,
      },
    ],
  },
  {
    text: '166. W RSBAC, czy każdy program może zmienić uprawnienia na inne niż te, na których został uruchomiony?',
    answers: [
      {
        text: 'zgodę wydaje oficer bezpieczeństwa modyfikując odpowiednio politykę bezpieczeństwa',
        correct: false,
      },
      { text: 'tak', correct: false },
      {
        text: 'każdorazowo musi otrzymać zgodę oficera bezpieczeństwa',
        correct: false,
      },
      { text: 'bezwzględnie nie', correct: true },
    ],
  },
  {
    text: '167. Skrót ACL oznacza:',
    answers: [
      { text: 'Added Control List', correct: false },
      { text: 'Access Control List', correct: true },
      { text: 'Lista uprawnień nadanych', correct: false },
      { text: 'Lista kontroli dostępu', correct: false },
    ],
  },
  {
    text: '168. Czy RSBAC zapewnia:',
    answers: [
      { text: 'wymuszanie stosowania skomplikowanych haseł', correct: false },
      { text: 'aktualizacje oprogramowania', correct: false },
      { text: 'stosowanie polityki MAC', correct: true },
      {
        text: 'system trudny do przechwycenia przez osobę niepowołaną',
        correct: false,
      },
      { text: 'poufność przechowywanych danych', correct: false },
      { text: 'stosowanie polityki DAC', correct: true },
    ],
  },
  {
    text: '169. Szyfrowanie asymetryczne:',
    answers: [
      {
        text: 'to używanie dwóch matematycznie zależnych kluczy',
        correct: true,
      },
      { text: 'jest wykorzystane przy podpisywaniu wiadomości', correct: true },
      {
        text: 'to używanie dwóch niezależnych kluczy: jednego do szyfrowania, drugiego do deszyfrowania',
        correct: false,
      },
      { text: 'nie jest wykorzystywane przez SSH', correct: false },
    ],
  },
  {
    text: '170. TUN/TAP to:',
    answers: [
      { text: 'rozszerzenie programu OpenVPN', correct: false },
      {
        text: 'sterownik działający tylko na systemach Windows',
        correct: false,
      },
      { text: 'sterownik działający tylko na systemach Linux', correct: false },
      { text: 'coś takiego nie istnieje', correct: false },
      {
        text: 'komponent pozwalający tworzyć wirtualne interfejsy sieciowe',
        correct: true,
      },
    ],
  },
  {
    text: '171. Możliwości uwierzytelniania przy użyciu SSH to:',
    answers: [
      { text: 'certyfikaty SSL X.509', correct: false },
      {
        text: 'para login, hasło naszego konta na zdalnym hoście',
        correct: true,
      },
      { text: 'samo hasło naszego konta na zdalnym hoście', correct: false },
      {
        text: 'klucz publiczny, używany przy szyfrowaniu symetrycznym',
        correct: false,
      },
      { text: 'trójka login, klucz publiczny i klucz prywatny', correct: true },
    ],
  },
  {
    text: '172. Protokół SSH umożliwia:',
    answers: [
      { text: 'pobieranie plików', correct: true },
      {
        text: 'bezpołączeniową komunikację ze zdalnym hostem, na którym uruchomiony jest serwer ssh',
        correct: false,
      },
      { text: 'nawiązywanie połączeń ze zdalnymi terminalami', correct: true },
    ],
  },
  {
    text: '173. Jakie restrykcje wprowadza tryb Safe w konfiguracji modułu PHP serwera WWW?',
    answers: [
      { text: 'blokowanie wybranych funkcji', correct: true },
      {
        text: 'ograniczenie dostępu do fragmentu systemu plików',
        correct: false,
      },
      {
        text: 'dostęp tylko do plików o tym samym właścicielu co skrypt',
        correct: true,
      },
      { text: 'ograniczenie zakresu zmiennych modyfikowanych', correct: true },
    ],
  },
  {
    text: '174. Serwer KDC:',
    answers: [
      { text: 'jest bardzo dobrze zabezpieczony', correct: true },
      {
        text: 'może zapewnić bardzo dobre bezpieczeństwo w sieci',
        correct: true,
      },
      {
        text: 'stosuje proste mechanizmy kryptograficzne, które są proste do złamania',
        correct: false,
      },
      {
        text: 'można prosto oszukać podszywając się pod niego',
        correct: false,
      },
      { text: 'ufa każdej usłudze', correct: false },
      { text: 'ufa uwiarygodnionym użytkownikom', correct: true },
      { text: 'ufa każdemu komputerowi w domenie', correct: false },
      {
        text: 'działa jedynie w obrębie jednej sieci lokalnej',
        correct: false,
      },
    ],
  },
  {
    text: '175. Wektor inicjujący w szyfrowaniu:',
    answers: [
      { text: 'musi być tajny i znany tylko odbiorcy', correct: false },
      {
        text: 'musi być tajny i znany obu stronom komunikacji',
        correct: false,
      },
      {
        text: 'powinien mieć losową wartość, za każdym razem inną',
        correct: true,
      },
      {
        text: 'wykorzystywany jest wyłącznie w szyfrowaniu asymetrycznym',
        correct: false,
      },
    ],
  },
  {
    text: '176. W uwierzytelnianiu z udziałem zaufanej trzeciej strony, do zadań tej trzeciej strony należy:',
    answers: [
      { text: 'poświadczenie uwierzytelnienia', correct: true },
      {
        text: 'pobranie listu uwierzytelniającego od jednej ze stron',
        correct: false,
      },
      {
        text: 'pobranie listu uwierzytelniającego od obu stron',
        correct: false,
      },
      { text: 'uwierzytelnienie jednej ze stron', correct: true },
    ],
  },
  {
    text: '177. W uwierzytelnianiu z udziałem zaufanej trzeciej strony, do zadań strony uwierzytelnianej należy:',
    answers: [
      {
        text: 'przekazanie poświadczenia uwierzytelnienia drugiej ze stron',
        correct: false,
      },
      {
        text: 'pobranie poświadczenie uwierzytelnienia od drugiej ze stron',
        correct: false,
      },
      {
        text: 'przekazanie danych uwierzytelniających drugiej ze stron',
        correct: false,
      },
      {
        text: 'przekazanie danych uwierzytelniających stronie trzeciej',
        correct: true,
      },
    ],
  },
  {
    text: '178. Zastosowanie rozszerzenia Enigmail w kliencie poczty Thunderbird pozwala na:',
    answers: [
      {
        text: 'używanie mechanizmu SSL do zapewniania bezpiecznych szyfrowanych kanałów komunikacyjnych z serwerem poczty POP',
        correct: false,
      },
      {
        text: 'wykorzystywanie PGP do szyfrowania i podpisywania wiadomości',
        correct: true,
      },
      { text: 'ochronę przed atakami man-in-the-middle', correct: false },
      {
        text: 'używanie mechanizm SSL do zapewniania bezpiecznych szyfrowanych kanałów komunikacyjnych z serwerem poczty SMTP',
        correct: false,
      },
    ],
  },
  {
    text: '179. Szyfr, w którym poddawana szyfrowaniu zostaje tej samej wielkości jednobajtowa porcja nieregularnie pojawiających się danych, nazywamy:',
    answers: [
      { text: 'strumieniowym', correct: true },
      { text: 'symetrycznym', correct: false },
      { text: 'blokowym', correct: false },
      { text: 'niesymetrycznym', correct: false },
    ],
  },
  {
    text: '180. Istotna przewaga podpisu elektronicznego nad odręcznym polega m. in. na:',
    answers: [
      {
        text: 'jest ściśle powiązany z treścią podpisywanego dokumentu',
        correct: true,
      },
      {
        text: 'weryfikacja podpisu wymaga tylko dostępu do certyfikatu klucza prywatnego podpisującego, co wystarcza do sądowego uznania podpisu za autentyczny',
        correct: false,
      },
      {
        text: 'autentyczność podpisu można zweryfikować poprzez prosta weryfikacje certyfikatu klucza publicznego podpisującego',
        correct: true,
      },
      {
        text: 'samo złożenie podpisu umożliwia wyparcie się tego przez podpisującego',
        correct: false,
      },
    ],
  },
  {
    text: '181. Proszę wskazać algorytmy wykorzystywane w HMAC:',
    answers: [
      { text: 'AES', correct: false },
      { text: 'SHA-4', correct: false },
      { text: 'SSH', correct: false },
      { text: 'ElGamal', correct: false },
      { text: 'Blowfish', correct: false },
      { text: 'Rijndael', correct: false },
      { text: 'MD5', correct: true },
      { text: 'żadne z powyższych', correct: false },
    ],
  },
  {
    text: '182. System NAC (Network Admission Control):',
    answers: [
      { text: 'oferują filtracje poczty elektronicznej', correct: false },
      {
        text: 'służą realizacji rozległych korporacyjnych sieci VPN',
        correct: false,
      },
      {
        text: 'to zapory sieciowe stosujące bezstanowe reguły filtracji',
        correct: false,
      },
      {
        text: 'umożliwiają blokowanie ruchu sieciowego ze stacji nie spełniających wymagań polityki bezpieczeństwa',
        correct: true,
      },
    ],
  },
  {
    text: '183. Metoda PING stosowana przez systemy IDS polega na wysłaniu:',
    answers: [
      {
        text: 'zapytania ICMP echo request pod adres MAC niezgodny z odpytywanym IP i oczekiwaniu na odpowiedź',
        correct: false,
      },
      {
        text: 'pakietów ICMP ping i porównaniu różnic w czasach odpowiedzi pomiędzy różnymi stanowiskami',
        correct: false,
      },
      {
        text: 'zapytania ICMP echo request pod adres rozgłoszeniowy i oczekiwaniu na odpowiedź',
        correct: true,
      },
      {
        text: 'zapytania ICMP echo request pod adres MAC podejrzanej stacji i oczekiwaniu na odpowiedź',
        correct: false,
      },
    ],
  },
  {
    text: '184. Cechy charakterystyczne ataku SYN flood to:',
    answers: [
      {
        text: 'intensywny strumień segmentów SYN skierowany na adres ofiary',
        correct: true,
      },
      {
        text: 'intensywny strumień segmentów SYN/ACK skierowany na adres ofiary',
        correct: false,
      },
      { text: 'brak segmentów SYN/ACK', correct: false },
      { text: 'brak segmentów ACK', correct: true },
    ],
  },
  {
    text: '185. Do szyfrów symetrycznych zaliczamy:',
    answers: [
      { text: 'IDEA', correct: true },
      { text: 'RSA', correct: false },
      { text: 'Rijndael', correct: true },
      { text: 'Blowfish', correct: true },
      { text: 'ElGamal', correct: false },
      { text: 'MD4', correct: false },
      { text: 'MD5', correct: false },
      { text: 'DES', correct: true },
      { text: 'RC4', correct: true },
      { text: 'RC2', correct: true },
      { text: 'AES', correct: true },
      { text: 'żadne z powyższych', correct: false },
    ],
  },
  {
    text: '186. Do szyfrów niesymetrycznych zaliczamy:',
    answers: [
      { text: 'MD4', correct: false },
      { text: 'Rijnadael', correct: false },
      { text: 'Blowfish', correct: false },
      { text: 'ElGamal', correct: true },
      { text: 'MD5', correct: false },
      { text: 'DES', correct: false },
      { text: 'żadne z powyższych', correct: false },
    ],
  },
  {
    text: '187. IPsec ESP umożliwia zapewnienie:',
    answers: [
      {
        text: 'autentyczności treści datagramu przy wykorzystaniu algorytmu MD5',
        correct: false,
      },
      {
        text: 'autentyczności treści datagramu przy wykorzystaniu algorytmu 3DES',
        correct: false,
      },
      { text: 'poufności treści datagramu w trybie tunelowym', correct: true },
      {
        text: 'poufności treści datagramu w trybie transportowym',
        correct: true,
      },
      {
        text: 'tylko autentyczności treści datagramu, nie poufności',
        correct: false,
      },
      {
        text: 'tylko poufności treści datagramu, nie autentyczności',
        correct: true,
      },
      {
        text: 'poufności i/lub autentyczności treści datagramu, w trybie synchronicznym',
        correct: false,
      },
      {
        text: 'poufności i/lub autentyczności treści datagramu, w trybie tunelowym',
        correct: true,
      },
    ],
  },
  {
    text: '188. Jaki mechanizm może wykorzystać administrator do dynamicznego uaktywnienia specjalnie przygotowanych reguł filtracji umożliwiających obejście ograniczeń narzuconych na normalny ruch sieciowy?',
    answers: [
      { text: 'zamek-i-klucz', correct: true },
      { text: 'dynamiczny skaner portów', correct: false },
      { text: 'sniffer dynamiczny', correct: false },
      { text: 'NIDS lub HIPS', correct: false },
    ],
  },
  {
    text: '189. Do czego służy protokół SMTP?',
    answers: [
      { text: 'pozwala na szyfrowania załączników wiadomości', correct: false },
      {
        text: 'pozwala na przesyłanie grupowych wiadomości w trybie multicast',
        correct: false,
      },
      {
        text: 'pozwala na przeszukiwanie bazy użytkowników na serwerze smtp w celu określenia adresata wiadomości',
        correct: false,
      },
      {
        text: 'pozwala na wysyłanie wiadomości do innych użytkowników',
        correct: true,
      },
    ],
  },
  {
    text: '190. Do czego służy komenda rlogin?',
    answers: [
      {
        text: 'pozwala tylko systemowym użytkownikom zalogowac sie na lokalna maszyne',
        correct: false,
      },
      { text: 'pozwala na zdalny dostęp do hosta', correct: true },
      {
        text: 'pozwala zalogowac sie lokalnym uzytkownikom na zdalna maszyne tylko na konto o takiej samej nazwie',
        correct: false,
      },
      {
        text: 'dostarcza zaawansowanego mechanizmu uwierzytelniania użytkowników logujących się na lokalna maszyne',
        correct: false,
      },
    ],
  },
  {
    text: '191. Co ma na celu publikowanie swojego klucza publicznego PGP?',
    answers: [
      {
        text: 'nic nie daje, publikowanie klucza ma na celu tylko usprawnienie mechanizmu wymiany kluczy między użytkownikami',
        correct: false,
      },
      {
        text: 'uniemożliwienie intruzowi podszycie się pod nasz e-mail',
        correct: false,
      },
      {
        text: 'umożliwienie zaszyfrowania wiadomości adresowanej do właściciela klucza',
        correct: true,
      },
      {
        text: 'umożliwienie sprawdzenia autentyczności listu wysłanego przez właściciela klucza',
        correct: true,
      },
      {
        text: 'umożliwienie odszyfrowania zawartości email wysłanej przez właściciela klucza',
        correct: false,
      },
    ],
  },
  {
    text: '192. Czy w systemie Ms Windows można skorzystać z szyfrowania PGP?',
    answers: [
      {
        text: 'niestety system ten nie wspiera szyfrowania PGP',
        correct: false,
      },
      {
        text: 'tak, ale tylko przy wykorzystaniu komercyjnych, płatnych programów',
        correct: false,
      },
      { text: 'tylko przy wykorzystaniu programu Ms Outlook', correct: false },
      {
        text: 'tak, jeżeli wykorzysta się odpowiednie oprogramowanie',
        correct: true,
      },
    ],
  },
  {
    text: '193. Szyfrowanie plików w systemie Ms Windows:',
    answers: [
      {
        text: 'jest dostępne dla każdego pod warunkiem korzystania z partycji typu NTFS',
        correct: true,
      },
      {
        text: 'jest dostępne wyłącznie dla administratora systemu',
        correct: false,
      },
      { text: 'jest niemożliwe', correct: false },
      {
        text: 'jest dostępna dla administratora systemu i operatora kopii bezpieczeństwa',
        correct: false,
      },
    ],
  },
  {
    text: '194. Wykorzystując stanowość zapory sieciowej możemy określić:',
    answers: [
      {
        text: 'odrzucić pakiety próbujące podszywać się pod rzekomo istniejące połączenia',
        correct: true,
      },
      {
        text: 'czy pakiet próbuje obejść nasz system bezpieczeństwa',
        correct: false,
      },
      { text: 'czy połączenie jest już ustanowione', correct: true },
      { text: 'czy pakiet zawiera flagę ACK', correct: false },
    ],
  },
  {
    text: '195. LMhash to:',
    answers: [
      {
        text: 'hasło administratora systemu zapisane w sposób jawny',
        correct: false,
      },
      {
        text: 'hasła użytkowników w postaci skrótów (hashy) wykorzystywane przez Lan Managera',
        correct: true,
      },
      {
        text: 'Lan Manager hash służący do identyfikacji systemu w sieci lokalnej',
        correct: false,
      },
      { text: 'hash numeru seryjnego systemu Ms Windows', correct: false },
    ],
  },
  {
    text: '196. Dziedziczenie uprawnień w systemie plików NTFS:',
    answers: [
      {
        text: 'uprawnienia sa pobierane bezpośrednio z uprawnień obiektu wyższego',
        correct: true,
      },
      { text: 'może przenieść również na system plików FAT64', correct: false },
      { text: 'jest identycznie z systemem plików ext3', correct: false },
      { text: 'nie istnieje w tym systemie plików', correct: false },
    ],
  },
  {
    text: '197. Wadą single-sign-on jest:',
    answers: [
      {
        text: 'relacja zaufania między parami hostów w domenie zaufania z wyłączeniem hosta zapewniającego uwierzytelnianie',
        correct: false,
      },
      {
        text: 'możliwość logowania się tylko na konta systemowe',
        correct: false,
      },
      {
        text: 'zależność od poprawnego działania uwierzytelniającej maszyny',
        correct: true,
      },
      {
        text: 'brak relacji zaufania między hostem uwierzytelniającym a hostem usługowym w domenie zaufania',
        correct: false,
      },
    ],
  },
  {
    text: '198. Aby serwer usług w domenie kerberos mógł działać wykorzystując uwierzytelniania Single-Sign-On, musi:',
    answers: [
      {
        text: 'używać odpowiednio zmodyfikowanych demonów usług, które potrafią rozmawiać z serwerem Kerberos',
        correct: true,
      },
      {
        text: 'używa zmodyfikowanego stosu IP, który współpracuje z serwerem KDC',
        correct: false,
      },
      {
        text: 'zapewnia sprzętowe szyfrowanie i generowanie liczb losowych',
        correct: false,
      },
      {
        text: 'używa specjalnego jądra systemu operacyjnego, wspierającego współpracę z serwerem KDC',
        correct: false,
      },
    ],
  },
  {
    text: '199. Nazwa domenowa komputera a nazwa domeny kerberos:',
    answers: [
      { text: 'musi być różna', correct: false },
      { text: 'musi być identyczna', correct: false },
      { text: 'zaleca się, aby była identyczna', correct: true },
      { text: 'zaleca się, aby byla rozna', correct: false },
    ],
  },
  {
    text: '200. Mechanizm TCP Wrapper:',
    answers: [
      {
        text: 'pozwala ograniczać dostęp do usług uruchamianych przez xinetd',
        correct: true,
      },
      {
        text: 'pozwala blokować spam przychodzący do serwera SMTP',
        correct: false,
      },
      {
        text: 'pozwala szyfrować ruch TCP z użyciem protokołów TLS/SSL',
        correct: false,
      },
      {
        text: 'powstał, aby wprowadzić silne uwierzytelnianie dla tzw. small services',
        correct: false,
      },
    ],
  },
  {
    text: '201. Tunel Net-to-Net to:',
    answers: [
      {
        text: 'koncepcja połączenia dwóch lub więcej sieci, w której istnieją zestawione tunele między bramami dla każdej z sieci w sieci Internet',
        correct: true,
      },
      {
        text: 'bezpośrednie połączenie typu proxy dwóch sieci przez Internet',
        correct: false,
      },
      {
        text: 'tunel zestawiany między systemami autonomicznymi w celu wymiany informacji o trasach routingu',
        correct: false,
      },
      {
        text: 'bezpośrednie połączenie dwóch lub więcej sieci przez Internet',
        correct: false,
      },
    ],
  },
  {
    text: '202. Klucz FEK to:',
    answers: [
      { text: 'klucz asymetryczny', correct: false },
      { text: 'klucz prywatny użytkownika', correct: false },
      { text: 'klucz publiczny użytkownika', correct: false },
      { text: 'klucz symetryczny', correct: true },
    ],
  },
  {
    text: '203. Połączenie pasywne ftp to:',
    answers: [
      {
        text: 'jeden z czterech rodzajów połączeń jakie moze nawiazac klient tj. połączenie danych, połączenie sterujące, połączenie aktywne, połączenie pasywne',
        correct: false,
      },
      {
        text: 'specjalny rodzaj szybkich połączeń przeznaczony do wysyłania dużych porcji danych do klientów',
        correct: false,
      },
      {
        text: 'połączenie, w którym klient informuje serwer, aby to on określił port a klient połączy się z tym portem i pobierze dane',
        correct: true,
      },
      {
        text: 'specjalny rodzaj połączeń dzięki którym możliwe jest połączenie w sytuacji gdy klient i serwer znajduja sie za firewallem realizujacym SNAT',
        correct: false,
      },
    ],
  },
  {
    text: '204. Połączenie aktywne ftp to:',
    answers: [
      {
        text: 'jeden z czterech rodzajów połączeń jakie moze nawiazac klient tj. połączenie danych, połączenie sterujące, połączenie aktywne, połączenie pasywne',
        correct: false,
      },
      {
        text: 'sytuacja, w której serwer ftp tworzy połączenie do klienta na losowy wybrany port przez klienta, aby przesłać żądany plik',
        correct: true,
      },
      {
        text: 'sytuacja w której specjalnie skonfigurowany serwer ftp potrafi przyjmować połączenia gdy sam znajduje się za firewallem realizującym usługę SNAT',
        correct: false,
      },
      {
        text: 'sytuacja w której przychodzące połączenie od serwera ftp do klienta ftp jest przekierowywane na firewallu do klienta znajdującego się w sieci lokalnej',
        correct: false,
      },
    ],
  },
  {
    text: '205. Skrót IKE oznacza:',
    answers: [
      { text: 'rodzaj algorytmów wymiany kluczy w FreeS/Wan', correct: false },
      {
        text: 'bardzo ważny element pakietu FreeS/Wan pozwalający tworzyć bezpieczne połączenie sterujące tunelami VPN',
        correct: true,
      },
      { text: 'Information Key Exchange', correct: false },
      {
        text: 'jeden z algorytmów szyfrowania w pakiecie FreeS/Wan',
        correct: false,
      },
    ],
  },
  {
    text: '206. Pakiet FreeS/Wan składa się z:',
    answers: [
      {
        text: 'z trzech komponentów: łata na jądro KLIPS, demon PLUTO, zestaw skryptów',
        correct: true,
      },
      { text: 'z dwóch protokołów: AH i ESP', correct: false },
      {
        text: 'z kilkunastu różnych algorytmów szyfrowania m.in. DES i 3DES oraz protokołu wymiany kluczy: ISAKMP',
        correct: false,
      },
    ],
  },
  {
    text: '207. Kryptografia oportunistyczna to:',
    answers: [
      {
        text: 'nowy rodzaj szyfrowania, bardzo wydajny i nie do złamania w dzisiejszych czasach z użyciem obecnych maszyn obliczeniowych',
        correct: false,
      },
      {
        text: 'automatyczny sposób negocjowania parametrów połączenia zaimplementowany w pakiecie FreeS/Wan',
        correct: true,
      },
      {
        text: 'eksperymentalny projekt nowego rodzaju szyfrowania rozwijany na potrzeby amerykańskiej Agencji Bezpieczeństwa Narodowego',
        correct: false,
      },
      {
        text: 'prosty rodzaj szyfrowania, nazwa "oportunistyczna" zaczerpnięta od francuskiego słowa: opportunisme oznaczającego "sprzyjający, dogodny"',
        correct: false,
      },
    ],
  },
  {
    text: '208. Narzędzie FreeS/Wan to:',
    answers: [
      {
        text: 'łata na jądro implementująca funkcjonalność ISec plus zestaw skryptów do zarządzania tym narzędziem',
        correct: false,
      },
      {
        text: 'program działający w przestrzeni użytkownika który posiada jeden plik konfiguracyjny zlokalizowany domyślnie: /etc/spiec',
        correct: false,
      },
      {
        text: 'narzędzie w formie łaty na jądro systemu Linux wraz z zestawem skryptów zarządzających oraz demon pozwalający wymieniać klucze',
        correct: true,
      },
      {
        text: 'narzędzie bardzo podobne do narzędzia Vtun służące do zestawiania połączeń VPN',
        correct: false,
      },
    ],
  },
  {
    text: '209. Tunel Host-to-host to:',
    answers: [
      {
        text: 'połączenie punkt - punkt między dwoma hostami, ale tylko na czas transmisji zaszyfrowanej',
        correct: true,
      },
      {
        text: 'połaczenie peer-to-peer z rezerwacja pasma na calej',
        correct: false,
      },
      {
        text: 'połączenie wykorzystujące już zestawione połączenie punkt-punkt dodające tylko szyfrowanie i uwierzytelnianie',
        correct: false,
      },
    ],
  },
  {
    text: '210. W jakich trybach może działać VPN:',
    answers: [
      { text: 'ruch sieciowy tunelowy i uwierzytelniany', correct: false },
      {
        text: 'ruch sieciowy nieszyfrowany ale uwierzytelniany',
        correct: false,
      },
      {
        text: 'ruch sieciowy szyfrowany ale nie uwierzytelniany',
        correct: false,
      },
      { text: 'ruch sieciowy tunelowany/transportowany', correct: true },
      {
        text: 'ruch sieciowy transportowany, szyfrowany i uwierzytelniany',
        correct: false,
      },
    ],
  },
  {
    text: '211. Skrót VPN to:',
    answers: [
      {
        text: 'szczególny rodzaj sieci vlan ale rozciągającej się na kilka sieci lokalnych rozdzielonych Internetem',
        correct: false,
      },
      { text: 'wirtualna sieć prywatna', correct: true },
      {
        text: 'dodatkowy model komunikacji wykorzystywany przez IPSec do zaufanych połączeń między urządzeniami sieciowymi takimi jak routery i switche, hosty',
        correct: false,
      },
      {
        text: 'szkieletowa sieć w Internecie przeznaczona dla zastosowań korporacyjnych zapewniająca wysoki stopień bezpieczeństwa np. w przypadku transakcji między bankami albo filiami tego samego banku połączonych Internetem',
        correct: false,
      },
    ],
  },
  {
    text: '212. Translacja typu DNAT charakteryzuje się:',
    answers: [
      {
        text: 'zamiana adresów źródłowych na inne (możliwe do wykorzystania na danym urządzeniu)',
        correct: false,
      },
      { text: 'nie ma translacji typu DNAT', correct: false },
      { text: 'zamiana adresów docelowych na inne', correct: true },
      {
        text: 'zamiana adresu źródłowego z adresem docelowym w konkretnym pakiecie',
        correct: false,
      },
    ],
  },
  {
    text: '213. Mechanizm SSO pozwala na:',
    answers: [
      { text: 'zapobieganie atakom typu XSS', correct: false },
      {
        text: 'zapobieganie atakom typu IP spoofing poprzez jawne podanie adresów IP w konfiguracji tego mechanizmu',
        correct: false,
      },
      {
        text: 'szyfrowanie ruchu sieciowego między zaufanymi hostami',
        correct: false,
      },
      { text: 'tworzenie relacji zaufania między hostami', correct: true },
    ],
  },
  {
    text: '214. Ukrycie widoczności systemu Ms Win spowoduje:',
    answers: [
      { text: 'niedziałanie zdalnego logowania do systemu', correct: false },
      { text: 'niedziałanie udostępniania zasobów', correct: true },
      { text: 'ukrycie systemu przed innymi systemami', correct: false },
      {
        text: 'ukrycie systemu tylko przed systemami typu Unix',
        correct: false,
      },
    ],
  },
  {
    text: '215. Wskaż cechy metody uwierzytelniania klienta wobec serwera z udziałem zaufanej trzeciej strony:',
    answers: [
      {
        text: 'serwer uwierzytelnia klienta na podstawie poświadczenia wystawionego przez trzecią stronę',
        correct: true,
      },
      {
        text: 'opłaca się stosować szczególnie wobec większej ilości serwerów',
        correct: true,
      },
      {
        text: 'serwer uwierzytelnia klienta poprzez hasło (np. jednorazowe)',
        correct: false,
      },
      {
        text: 'serwer uwierzytelnia klienta metoda challenge-response',
        correct: false,
      },
    ],
  },
  {
    text: '216. Flaga suid wg standardu POSIX 1003.1:',
    answers: [
      {
        text: 'oznacza przejęcie przez proces uprawnień właściciela pliku, z którego proces został uruchomiony',
        correct: true,
      },
      {
        text: 'oznacza, że usunięcie i zmiana nazwy pliku są możliwe tylko przez właściciela samego pliku (lub właściciela katalogu)',
        correct: false,
      },
      { text: 'może być nadawana dla plików wykonywalnych', correct: true },
      { text: 'ma sens tylko w przypadku katalogów', correct: false },
    ],
  },
  {
    text: '217. Wskaż cechy filtracji bezstanowej realizowanej przez zapory sieciowe:',
    answers: [
      {
        text: 'dopasowuje pakiety do zapamiętanej historii komunikacji',
        correct: false,
      },
      {
        text: 'pozwala uniknąć niepotrzebnego sprawdzania reguł dla pakietów powracających w ruchu zweryfikowanym w strone przeciwna',
        correct: false,
      },
      { text: 'wymaga sprawdzania reguł dla każdego pakietu', correct: true },
      {
        text: 'historia komunikacji nie ma wpływu na decyzje zapory',
        correct: true,
      },
    ],
  },
  {
    text: '218. Koncepcja "zamkniętych grup użytkowników" dotyczy odseparowania danych przetwarzanych przez odrębne grupy użytkowników tego samego środowiska sieciowego. Które z poniższych mechanizmów sa realizacja tej koncepcji:',
    answers: [
      { text: 'uwięzienie (jail)', correct: true },
      { text: 'protokół rezerwacji zasobów (RSVP)', correct: false },
      {
        text: 'transmisja grupowa (multicast) w sieci Ethernet',
        correct: false,
      },
      { text: 'sieci wirtualne VLAN', correct: true },
    ],
  },
  {
    text: '219. Wskaż cechy protokołu Hot Standby Routing Protocol:',
    answers: [
      {
        text: 'oferuje transparentne zasilanie z kilku redundantnych torów energetycznych',
        correct: false,
      },
      { text: 'jest wykorzystywany w LAN Emulation', correct: false },
      {
        text: 'chroni przed atakami DoS poprzez czasowe wyłączenie routingu po wykryciu próby ataku',
        correct: false,
      },
      {
        text: 'oferuje transparentna redundancje urządzeń sieciowych',
        correct: true,
      },
    ],
  },
  {
    text: '220. Wskaż kiedy system kontroli dostępu MAC może zezwolić podmiotowi P na dopisanie danych do zasobu Z:',
    answers: [
      {
        text: 'gdy zbiór kategorii przynależności danych Z zawiera się w zbiorze kategorii P',
        correct: false,
      },
      { text: 'gdy poziom zaufania P jest niższy niż Z', correct: true },
      { text: 'gdy poziom zaufania P jest wyższy niż Z', correct: false },
      { text: 'gdy poziom zaufania P jest wyższy niż Z', correct: false },
    ],
  },
  {
    text: '221. Wskaż kiedy system kontroli dostępu MAC nie zezwoli podmiotowi P na dopisanie danych do zasobu Z:',
    answers: [
      {
        text: 'gdy zbiory kategorii przynależności danych P i Z są rozłączne',
        correct: true,
      },
      {
        text: 'gdy zbiór kategorii przynależności danych Z zawiera się w zbiorze kategorii P',
        correct: false,
      },
      { text: 'gdy poziom zaufania Z jest niższy niż P', correct: false },
      { text: 'gdy poziom zaufania Z jest wyższy niż P', correct: true },
    ],
  },
  {
    text: '222. Mechanizm SSO (single-sign-on):',
    answers: [
      {
        text: 'służy ochronie danych uwierzytelniających użytkownika',
        correct: true,
      },
      {
        text: 'pozwala jednolicie chronić podpisem cyfrowym poufność całej komunikacji',
        correct: false,
      },
      {
        text: 'służy ochronie niezaprzeczalności danych składowanych w repozytorium',
        correct: false,
      },
      {
        text: 'pozwala jednolicie chronić podpisem cyfrowym integralność całej komunikacji',
        correct: false,
      },
    ],
  },
  {
    text: '223. Statyczne reguły filtracji (filtracja bezstanowa) nie radzą sobie z precyzyjna filtracja ruchu:',
    answers: [
      { text: 'HTTP, gdy serwer pracuje w trybie bezstanowym', correct: false },
      { text: 'HTTP, gdy serwer pracuje w trybie stanowym', correct: false },
      { text: 'FTP, gdy serwer pracuje w trybie aktywnym', correct: true },
      { text: 'FTP, gdy serwer pracuje w trybie pasywnym', correct: false },
    ],
  },
  {
    text: '224. Standard IEEE 802.1x:',
    answers: [
      {
        text: 'realizuje autoryzację i kontrolę dostępu do lokalnej infrastruktury sieciowej',
        correct: true,
      },
      {
        text: 'współpracuje z protokołami takimi jak RADIUS lub TACACS+',
        correct: true,
      },
      { text: 'dotyczy zabezpieczenia poufności', correct: false },
      {
        text: 'dotyczy uprawnień dostępu do zasobów plikowych',
        correct: false,
      },
    ],
  },
  {
    text: '225. Algorytm 3DES w trybie EDE wykorzystuje klucze o długości:',
    answers: [
      { text: '256b', correct: false },
      { text: '116b', correct: false },
      { text: '64b', correct: false },
      { text: '192b', correct: true },
    ],
  },
  {
    text: '226. Wskaż cechy charakteryzujące kontrole dostępu MAC:',
    answers: [
      {
        text: 'właściciel zasobu nie może przekazać możliwość decydowania o uprawnieniach dostępu do tego zasobu',
        correct: true,
      },
      {
        text: 'właściciel zasobu może przekazać możliwość decydowania o uprawnieniach dostępu do tego zasobu',
        correct: false,
      },
      {
        text: 'właściciel zasobu nie może decydować o uprawnieniach dostępu do tego zasobu',
        correct: true,
      },
      {
        text: 'właściciel zasobu może decydować o uprawnieniach dostępu do tego zasobu',
        correct: false,
      },
      {
        text: 'tylko właściciel zasobu może dysponować prawami dostępu do tego zasobu',
        correct: false,
      },
      {
        text: 'tylko wyróżniony oficer bezpieczeństwa może dysponować prawami dostępu do zasobów',
        correct: true,
      },
      {
        text: 'etykiety ochrony danych przypisane do zasobów automatycznie wymuszają uprawnienia',
        correct: true,
      },
    ],
  },
  {
    text: '227. Który z wymienionych protokołów nie chroni przed podszywaniem się pod podmiot uwierzytelniający:',
    answers: [
      { text: 'SSL v3', correct: false },
      { text: 'SSL v2', correct: false },
      { text: 'TLS v1', correct: false },
      { text: 'PAP', correct: true },
    ],
  },
  {
    text: '228. Który z wymienionych protokołów nie chroni przed podszywaniem się pod podmiot uwierzytelniający:',
    answers: [
      { text: 'IPsec/IKE', correct: false },
      { text: 'IPsec/ISAKMP', correct: false },
      { text: 'PAP', correct: true },
      { text: 'SSL', correct: false },
    ],
  },
  {
    text: '229. Wskaż przykłady zamaskowanych kanałów komunikacyjnych:',
    answers: [
      { text: 'system plików (tworzenie / usuwanie pliku)', correct: true },
      { text: 'obciążenie procesora', correct: true },
      { text: 'SSL', correct: false },
      { text: 'VPN', correct: false },
    ],
  },
  {
    text: '230. Wskaż cechy certyfikatów kwalifikowanych (wg obowiązującego prawodawstwa polskiego):',
    answers: [
      { text: 'ważne są nie dłużej niż 2 lata', correct: false },
      { text: 'służą do szyfrowania dokumentów', correct: false },
      { text: 'służą do szyfrowania poczty', correct: false },
      {
        text: 'wywołują skutki prawne równoważne podpisowi własnoręcznemu',
        correct: true,
      },
    ],
  },
  {
    text: '231. Który protokół umożliwia transparentna dla stacji sieciowej obsługę uszkodzenia jej routera domyślnego?',
    answers: [
      { text: 'RIP (Routing Information Protocol)', correct: false },
      { text: 'TRP (Transparent Router Protocol)', correct: false },
      { text: 'LSP (Link State Protocol)', correct: false },
      { text: 'HSRP (Hot Standby Routing Protocol)', correct: true },
    ],
  },
  {
    text: '232. Wskaż własności protokołu HSRP (Hot Standby Router Protocol):',
    answers: [
      { text: 'służy do tworzenia tuneli VPN', correct: false },
      { text: 'zabezpiecza poczte elektroniczna', correct: false },
      { text: 'pozwala uzyskać redundancje routerów', correct: true },
      { text: 'wspomaga uwierzytelnianie', correct: false },
    ],
  },
  {
    text: '233. Wskaż najbezpieczniejszy standard zabezpieczeń komunikacji w sieciach bezprzewodowych Wi-Fi:',
    answers: [
      { text: 'IEEE 802.11 WEP', correct: false },
      { text: 'IEEE 802.11i WPA', correct: false },
      { text: 'WPA-Enterprise', correct: true },
      { text: 'WPA-PSK', correct: false },
    ],
  },
  {
    text: '234. Które z poniższych standardów nie oferują żadnej redundancji:',
    answers: [
      { text: 'RAID 0', correct: true },
      { text: 'RAID 5', correct: false },
      { text: 'RAID 3', correct: false },
      { text: 'RAID 1', correct: false },
    ],
  },
  {
    text: '235. Ktora klasa RAID zapewnia odpornosc na jednoczesna awarie 2 dyskow w 5-dyskowej macierzy?',
    answers: [
      { text: 'RAID 2', correct: false },
      { text: 'RAID 1', correct: false },
      { text: 'RAID 6', correct: true },
      { text: 'żadna z powyższych', correct: false },
    ],
  },
  {
    text: '236. Program xinetd to:',
    answers: [
      {
        text: 'ważny element systemu operacyjnego Linux, odpowiedzialny za uruchamianie innych programów',
        correct: true,
      },
      {
        text: 'krytyczny program w systemie operacyjnym Linux, który zawsze musi być uruchomiony',
        correct: false,
      },
      {
        text: 'krytyczny program w systemie operacyjnym Linux, który zawsze musi być uruchomiony, jest rodzicem dla wszystkich nowo powstałych procesów',
        correct: false,
      },
      {
        text: 'bardzo ważny komponent systemu Linux, bez którego system operacyjny nie będzie działał prawidłowo z uwagi na niemoznosc uruchamiania dodatkowych programów',
        correct: false,
      },
    ],
  },
  {
    text: '237. Relacja zaufania w uwierzytelnianiu w środowisku sieciowym:',
    answers: [
      {
        text: 'jest wykorzystywana zarówno przez systemy Unix, jak i MS Windows',
        correct: true,
      },
      { text: 'może być jednostronna lub dwustronna', correct: true },
      { text: 'nie jest przechodnia', correct: false },
      { text: 'jest realizacją koncepcji SSO', correct: false },
    ],
  },
  {
    text: '238. Mechanizm ACL umożliwia:',
    answers: [
      {
        text: 'nadawanie praw (rwx) wielu użytkownikom i grupom',
        correct: true,
      },
      { text: 'odtwarzanie zniszczonych plików', correct: false },
      {
        text: 'nadawanie nowych praw (np. dopisywania) wielu użytkownikom',
        correct: true,
      },
      { text: 'ustanowienie szyfrowania plików', correct: false },
    ],
  },
  {
    text: '239. Jakie restrykcje pozwala narzucić systemowa funkcja chroot() systemu Unix?',
    answers: [
      {
        text: 'ograniczenie odczytu do określonego poddrzewa systemu plików',
        correct: true,
      },
      {
        text: 'ograniczenie komunikacji sieciowej do wybranych portów',
        correct: false,
      },
      { text: 'niedostępność odziedziczonych deskryptorów', correct: false },
      {
        text: 'ograniczenie zapisu do określonego poddrzewa systemu plików',
        correct: true,
      },
    ],
  },
  {
    text: '240. Które z poniższych mechanizmów stosują programy malware w celu kamuflażu swojej obecności:',
    answers: [
      { text: 'opancerzenie (armor)', correct: true },
      { text: 'zamaskowane węzły (shadow i-node)', correct: true },
      { text: 'fingerprinting', correct: false },
      { text: 'polimorfizm', correct: true },
    ],
  },
  {
    text: '241. SFTP to:',
    answers: [
      {
        text: 'klient protokołu FTP będący częścią pakietu SSH',
        correct: false,
      },
      { text: 'niezależna implementacja protokołu Secure FTP', correct: false },
      {
        text: 'SSL FTP , czyli wersja protokołu FTP wykorzystująca mechanizm certyfikatów SSL',
        correct: false,
      },
      { text: 'podsystem SSH służący do przesyłania plików', correct: true },
      { text: 'podsystem raportowania o błędach w SSH', correct: false },
    ],
  },
  {
    text: '242. Które zdania poprawnie opisują nawiązywanie sesji SSL?',
    answers: [
      {
        text: 'serwer przesyła komunikat ServerHello ze swoim certyfikatem',
        correct: true,
      },
      {
        text: 'klient uwierzytelnia serwer na podstawie odebranego certyfikatu',
        correct: true,
      },
      {
        text: 'serwer przesyła komunikat ServerHello z opcjonalnym losowym zawołaniem',
        correct: false,
      },
      {
        text: 'klient odsyła podpisane zawołanie do serwera tylko jeśli serwer zadał uwierzytelnienia klienta',
        correct: true,
      },
    ],
  },
  {
    text: '243. Które z wymienionych protokołów i standardów oferują szyfrowaną transmisję wiadomości pocztowych?',
    answers: [
      { text: 'X.400', correct: false },
      { text: 'S/MIME', correct: true },
      { text: 'PGP', correct: true },
      { text: 'SMTP', correct: false },
    ],
  },
  {
    text: '244. Wskaż możliwe środki ochronne przed atakami przepełnienia bufora:',
    answers: [
      { text: 'niewykonywany segment kodu', correct: true },
      { text: 'niewykonywany segment stosu', correct: true },
      {
        text: 'kontrola zakresu danych globalnych programu na etapie wykonania',
        correct: false,
      },
      {
        text: 'kontrola zakresu danych lokalnych funkcji na etapie kompilacji',
        correct: false,
      },
    ],
  },
  {
    text: '245. Wskaż szyfry symetryczne:',
    answers: [
      { text: 'Blowfish', correct: true },
      { text: 'DES', correct: true },
      { text: 'ElGamal', correct: false },
      { text: 'żadne z powyższych', correct: false },
    ],
  },
  {
    text: '246. Protokół IPv6:',
    answers: [
      {
        text: 'oferuje mechanizm AH w celu zapewnienia autentyczności',
        correct: true,
      },
      {
        text: 'oferuje mechanizm ESP w celu zapewnienia poufności',
        correct: true,
      },
      {
        text: 'nie oferuje AH, jako że jego zadania powiela ESP',
        correct: false,
      },
      {
        text: 'nie oferuje żadnych mechanizmów bezpieczeństwa (wymaga dodatkowej implementacji IPsec)',
        correct: false,
      },
    ],
  },
  {
    text: '247. Która zasada realizacji zabezpieczeń wymaga konsekwentnego zastosowania odpowiedniego mechanizmu ochrony wobec wszystkich wykorzystywanych protokołów aplikacyjnych:',
    answers: [
      { text: 'spójności poziomej', correct: true },
      { text: 'spójności pionowej', correct: false },
      { text: 'naturalnego styku', correct: false },
      { text: 'obligatoryjnej kontroli dostępu', correct: false },
    ],
  },
  {
    text: '248. Moduły PAM (Pluggable Authentication Modules) umożliwiają:',
    answers: [
      {
        text: 'oddzielenie konfiguracji procesu uwierzytelniania od kodu aplikacji',
        correct: true,
      },
      {
        text: 'integrację uwierzytelniania użytkowników sieci pomiędzy systemami Windows i Linux',
        correct: false,
      },
      {
        text: 'dostęp serwera usługi www (np. z systemu operacyjnego MS Windows w środowisku domenowym) do zewnętrznych źródeł danych uwierzytelniających, np. bazy danych',
        correct: true,
      },
      {
        text: 'implementuje filtry Bayesa do ochrony poczty przed niepożądanymi przesyłkami',
        correct: false,
      },
    ],
  },
  {
    text: '249. Okresl prawidlowa kolejnosc pelnej sekwencji odwolan klienta do serwerow w przypadku dostepu do uslugi SMTP w środowisku Kerberos:',
    answers: [
      {
        text: 'serwer TGS - serwer AS - serwer TGS - serwer SMTP',
        correct: false,
      },
      {
        text: 'serwer AS - serwer TGS - serwer SMTP - serwer AS',
        correct: false,
      },
      { text: 'serwer AS - serwer TGS - serwer SMTP', correct: true },
      { text: 'serwer TGS - serwer AS - serwer SMTP', correct: false },
    ],
  },
  {
    text: '250. Które protokoły umożliwiają propagacje portów w tunelu kryptograficznym?',
    answers: [
      { text: 'ESP', correct: false },
      { text: 'SSH', correct: true },
      { text: 'SSL', correct: true },
      { text: 'AH', correct: false },
    ],
  },
  {
    text: '251. Standard SASL (Simple Authentication and Security Layer) umożliwia:',
    answers: [
      {
        text: 'rozszerzenie mechanizmu uwierzytelniania protokołu SMTP o mechanizm haseł jednorazowych',
        correct: true,
      },
      {
        text: 'rozszerzenie mechanizmu uwierzytelniania protokołu IMAP o współpracę z systemem Kerberos',
        correct: true,
      },
      {
        text: 'rozszerzenie mechanizmu kontroli dostępu do katalogu domowego o listy ACL',
        correct: false,
      },
      {
        text: 'redukcje mechanizmu kontroli dostępu do plików w Windows do postaci rwx',
        correct: false,
      },
    ],
  },
  {
    text: '252. Które zdania poprawnie opisują proces uwierzytelniania w usłudze pocztowej?',
    answers: [
      {
        text: 'standard ESMTP umozliwia uwierzytelnianie metoda zawolanie-odzew',
        correct: true,
      },
      {
        text: 'standard SMTP umozliwia uwierzytelnianie metoda zawolanie-odzew',
        correct: false,
      },
      {
        text: 'w standardzie SMTP serwery uwierzytelniane są na podstawie adresów',
        correct: true,
      },
      {
        text: 'standard ESMTP oferuje mechanizmy uwierzytelniania SASL i TLS',
        correct: true,
      },
    ],
  },
  {
    text: '253. Ochronę SYSKEY wprowadzono w systemie MS Windows w celu:',
    answers: [
      {
        text: 'szyfrowania plików użytkowników w systemie NTFS',
        correct: false,
      },
      {
        text: 'wzmocnionego szyfrowania postaci hash haseł użytkowników',
        correct: true,
      },
      {
        text: 'odszyfrowania plików przez systemowa usługę odzyskiwania plików',
        correct: false,
      },
      {
        text: 'szyfrowania plików systemowych w systemie NTFS',
        correct: false,
      },
    ],
  },
  {
    text: '254. Skrót KDC w systemie Kerberos oznacza:',
    answers: [
      { text: 'Key Distribution Center', correct: true },
      { text: 'Kerberos Domain Controller', correct: false },
      { text: 'Kerberos Directory Center', correct: false },
      { text: 'Kerberos Designated Certificate', correct: false },
    ],
  },
  {
    text: '255. Funkcja skrótu dająca wynik 512-bitowy:',
    answers: [
      { text: 'ma teoretyczna odpornosc na kolizje = 2^256', correct: true },
      { text: 'wymaga klucza 512b', correct: false },
      { text: 'wymaga klucza 256b', correct: false },
      {
        text: 'ma teoretyczna odpornosc na atak urodzinowy = 2^256',
        correct: true,
      },
    ],
  },
  {
    text: '256. Jakie komponenty tworzą każdą zaporę sieciowa?',
    answers: [
      { text: 'dekoder ramek PDU', correct: true },
      { text: 'filtr pakietów', correct: true },
      { text: 'sniffer pakietów', correct: false },
      { text: 'skaner portów', correct: false },
    ],
  },
  {
    text: '257. Wskaż operacje stosowane w metodzie ARP cache detekcji snifferów:',
    answers: [
      {
        text: 'wysłanie zapytania ICMP echo request z fałszywym adresem źródłowym IP na adres podejrzewanej stacji',
        correct: true,
      },
      { text: 'wysłanie ogłoszenia ARP o fałszywym adresie IP', correct: true },
      {
        text: 'wysłanie zapytania ICMP echo request z fałszywym adresem docelowym IP i oczekiwaniu na odpowiedź',
        correct: false,
      },
      {
        text: 'odpytanie podejrzewanej stacji o wszystkie adresy MAC sieci lokalnej',
        correct: false,
      },
    ],
  },
  {
    text: '258. Jaka usługa jest szczególnie narażona na atak TCP spoofing?',
    answers: [
      {
        text: 'FTP, ponieważ domyślnie serwery działają w trybie pasywnym',
        correct: false,
      },
      {
        text: 'FTP, ponieważ domyślnie serwery działają w trybie aktywnym',
        correct: false,
      },
      {
        text: 'RCP, ponieważ używa adresu klienta do uwierzytelnienia',
        correct: true,
      },
      {
        text: 'RCP, ponieważ nie używa adresu klienta do uwierzytelnienia',
        correct: false,
      },
    ],
  },
  {
    text: '259. Przykładem realizacji mechanizmu uwierzytelniania z udziałem zaufanej trzeciej strony jest:',
    answers: [
      { text: 'protokół Kerberos', correct: true },
      { text: 'urząd CA', correct: false },
      { text: 'system PKI', correct: false },
      { text: 'protokół Diffiego-Hellmana', correct: false },
    ],
  },
  {
    text: '260. Mechanizm OTP (one-time passwords):',
    answers: [
      {
        text: 'uniemożliwia atak poprzez odtwarzanie (replaying)',
        correct: true,
      },
      {
        text: 'weryfikuje nietrywialność hasła podczas jego zmiany',
        correct: false,
      },
      { text: 'jest niewrażliwy na podsłuch', correct: true },
      {
        text: 'uniemożliwia zdobycie hasła metodą przeszukiwania wyczerpującego',
        correct: false,
      },
    ],
  },
  {
    text: '261. Które z wymienionych technik mogą być wykorzystane do uwierzytelniania z hasłami jednorazowymi:',
    answers: [
      { text: 'jednokrotne uwierzytelniane (single sign-on)', correct: false },
      { text: 'certyfikacja klucza sesji', correct: false },
      { text: 'metoda zawołanie-odzew (challenge-response)', correct: true },
      { text: 'synchronizacja czasu', correct: true },
    ],
  },
  {
    text: '262. Które z poniższych reguł są prawdziwe w przypadku mechanizmu Mandatory Access Control (MAC). Podmiot nie może …',
    answers: [
      {
        text: 'zapisać danych o etykiecie niższej niż jego aktualna',
        correct: true,
      },
      {
        text: 'uruchomić procesu o etykiecie wyższej niż jego aktualna',
        correct: false,
      },
      {
        text: 'zapisać danych o etykiecie wyższej niż jego aktualna',
        correct: false,
      },
      {
        text: 'czytaj danych o etykiecie niższej niż jego aktualna',
        correct: false,
      },
    ],
  },
  {
    text: '263. Jakie funkcje moga pelnic systemy HIPS?',
    answers: [
      { text: 'sondowanie usług (port enumeration)', correct: false },
      { text: 'zamek-i-klucz', correct: false },
      { text: 'monitor antywirusowy', correct: true },
      { text: 'ochrona przed atakami DoS', correct: true },
    ],
  },
  {
    text: '264. Do zrealizowania zamaskowanego kanału komunikacyjnego może potencjalnie posłużyć:',
    answers: [
      { text: 'port szeregowy', correct: true },
      { text: 'kolejka drukowania', correct: true },
      { text: 'system plików', correct: true },
      { text: 'obciążenie systemu', correct: true },
    ],
  },
  {
    text: '265. Wskaż warunek wystarczający do weryfikacji podpisu cyfrowego wiadomości S/MIME:',
    answers: [
      {
        text: 'uprzednie przesłanie do nadawcy klucza publicznego odbiorcy',
        correct: false,
      },
      {
        text: 'uprzednie przesłanie do odbiorcy klucza publicznego nadawcy',
        correct: false,
      },
      {
        text: 'dostęp do centrum CA w celu pobrania certyfikatu wskazanego w podpisie (i innych certyfikatów na ścieżce certyfikacji)',
        correct: true,
      },
      {
        text: 'wymiana kluczy między nadawcą a odbiorcą metodą Diffiego-Hellmana',
        correct: false,
      },
    ],
  },
  {
    text: '266. Jakie właściwości można ustawić w Zasadach haseł w systemie Windows?',
    answers: [
      { text: 'złożoność haseł', correct: true },
      { text: 'maksymalna długość nazwy użytkownika', correct: false },
      { text: 'minimalna długość nazwy użytkownika', correct: false },
      { text: 'włączenie szyfrowania AES haseł użytkowników', correct: false },
      { text: 'minimalna długość hasła użytkownika', correct: true },
    ],
  },
  {
    text: '267. Systemowa zapora sieciowa w systemie Windows:',
    answers: [
      {
        text: 'pozwala zestawiać tunel IPsec domyślnie szyfrując dane algorytmem 3DES',
        correct: false,
      },
      { text: 'może monitorować parametry asocjacji IPsec', correct: true },
      {
        text: 'pozwala zestawiać tunel IPsec domyślnie szyfrując dane algorytmem AES',
        correct: true,
      },
      { text: 'może monitorować parametry asocjacji ISAKMP', correct: false },
    ],
  },
  {
    text: '268. Lokalna zapora sieciowa systemu Windows na stanowisku X zablokowała możliwość zdalnego odpytywania o dostępność X przy pomocy narzędzia ping, pozostawiając jednak możliwość zdalnego dostępu do serwera www w tym systemie. Mogła to osiągnąć poprzez:',
    answers: [
      {
        text: 'wyłączenie obsługi przychodzących komunikatów ICMP echo',
        correct: true,
      },
      { text: 'odrzucanie całego ruchu ICMP', correct: false },
      {
        text: 'zablokowanie komunikacji z siecią dla programu ping',
        correct: false,
      },
      {
        text: 'wyłączenie ruchu IP na wszystkich interfejsach, ale pozostawienie dostępu do wskazanych portów TCP',
        correct: false,
      },
    ],
  },
  {
    text: '269. Użytkownik U systemu Unix należący do grupy G1 nie ma wpisu na liście ACL do zasobu O w systemie plików. Jednak grupie G1 na liście ACL tego zasobu nadano prawa r i w, natomiast wszystkim pozostałym (others) - prawa r oraz x. Które efektywne uprawnienia do O posiada U? (U nie jest właścicielem O i nie należy do grupy zasobu O):',
    answers: [
      { text: 'r', correct: true },
      { text: 'w', correct: true },
      { text: 'x', correct: false },
      { text: 'żadne', correct: false },
    ],
  },
  {
    text: '270. Zasoby systemu operacyjnego MS Windows udostępnione poprzez SMB:',
    answers: [
      {
        text: 'mogą mieć ograniczony dostęp do odczytu i/lub zapisu tylko dla wskazanych użytkowników',
        correct: true,
      },
      { text: 'nazywa się udziałami', correct: true },
      { text: 'nazywa się portami', correct: false },
      {
        text: 'przy dostępie zdalnym zawsze wymagane jest logowanie (podawanie hasła)',
        correct: false,
      },
      {
        text: 'tylko użytkownicy, którzy posiadają lokalne konto w systemie operacyjnym mogą uzyskać zdalny dostęp do zasobu',
        correct: false,
      },
    ],
  },
  {
    text: '271. ssh -L 9999:cerber:23 polluks Wybierz prawdziwe stwierdzenia dotyczące powyższego polecenia:',
    answers: [
      {
        text: 'ruch między między lokalnym komputerem a polluksem będzie szyfrowany',
        correct: true,
      },
      {
        text: 'dane kierowane na port 9999 systemu cerber zostaną przesłane w zaszyfrowanej formie na port 23 systemu polluks',
        correct: false,
      },
      {
        text: 'dane kierowane na port 9999 systemu cerber zostaną przesłane w niezabezpieczonej formie na port 23 systemu polluks',
        correct: false,
      },
      {
        text: 'w wyniku polecenia zestawiony zostanie zabezpieczony tunel między systemem cerberem a polluksem',
        correct: false,
      },
    ],
  },
  {
    text: '272. Kto może nadawać/modyfikować uprawnienia POSIX ACL danego obiektu w systemie plików:',
    answers: [
      {
        text: "właściciel obiektu, ale pod warunkiem, że posiada prawo 'w'",
        correct: false,
      },
      {
        text: "właściciel obiektu, niezależnie od posiadania prawa 'w'",
        correct: true,
      },
      {
        text: 'dowolny użytkownik posiadający prawo modyfikacji pliku',
        correct: false,
      },
      { text: 'administrator (root)', correct: true },
    ],
  },
  {
    text: '273. Mechanizm SUID/SGID:',
    answers: [
      {
        text: 'SUID zawsze powoduje wykonanie aplikacji z uprawnieniami grupy właściciela aplikacji',
        correct: false,
      },
      {
        text: 'SUID zawsze powoduje wykonanie aplikacji z uprawnieniami administratorskimi',
        correct: false,
      },
      {
        text: 'SGID zawsze powoduje wykonanie aplikacji z uprawnieniami administratorskimi',
        correct: false,
      },
      {
        text: 'SGID zawsze powoduje wykonanie aplikacji z uprawnieniami grupy właściciela aplikacji',
        correct: true,
      },
    ],
  },
  {
    text: '274. Wpisy ACE (na liście ACL) zabraniające dostępu:',
    answers: [
      {
        text: 'występują tylko w przypadku zwirtualizowanych aplikacji w MS Windows',
        correct: false,
      },
      { text: 'nie są dziedziczone wgłąb katalogu', correct: false },
      { text: 'występują tylko w POSIX ACL', correct: false },
      {
        text: 'mają priorytet nad wpisami ACE przyznającymi dostęp',
        correct: true,
      },
    ],
  },
  {
    text: '275. Jakie metody uwierzytelniania oferuje protokół HTTP:',
    answers: [
      {
        text: 'obustronne uwierzytelnianie metodą Diffiego-Hellmana',
        correct: false,
      },
      {
        text: 'uwierzytelnianie serwera poprzez certyfikat X.509',
        correct: true,
      },
      {
        text: 'uwierzytelnianie klienta poprzez userame token (username+password)',
        correct: true,
      },
      {
        text: 'uwierzytelnianie klienta metodą digest (z użyciem funkcji skrótu)',
        correct: true,
      },
    ],
  },
  {
    text: '276. Trusted Platform Module (TPM) może być wykorzystywany do:',
    answers: [
      {
        text: 'przechowywania kluczy kryptograficznych używanych przez aplikacje w systemie operacyjnym',
        correct: true,
      },
      {
        text: 'uwierzytelniania podmiotu przy wystawianiu certyfikatu przez urząd CA w systemie PKI',
        correct: false,
      },
      {
        text: 'podejmowania decyzji o autoryzacji w systemie kontroli dostępu MAC',
        correct: false,
      },
      {
        text: 'wykonywania operacji kryptograficznych zlecanych przez aplikacje w systemie operacyjnym',
        correct: true,
      },
    ],
  },
  {
    text: '277. Czy zaszyfrowany plik w systemie MS Windows możemy współdzielić z innym użytkownikiem?',
    answers: [
      {
        text: 'tylko pod warunkiem przekazania temu użytkownikowi swojego klucza prywatnego',
        correct: false,
      },
      {
        text: 'tylko pod warunkiem przekazania temu użytkownikowi swojego klucza publicznego',
        correct: false,
      },
      { text: 'nie jest to możliwe', correct: false },
      {
        text: 'pod warunkiem posiadania certyfikatu EFS tego użytkownika',
        correct: true,
      },
    ],
  },
  {
    text: '278. W jaki sposób można jednoznacznie określić, które konto w systemie operacyjnym MS Windows jest wbudowanym kontem administracyjnym?',
    answers: [
      {
        text: 'Aktualnie nie ma jednego wbudowanego konta administracyjnego- każde konto użytkownika może posiadać takie uprawnienia po odpowiedniej konfiguracji',
        correct: false,
      },
      { text: 'konto takie ma zawsze nazwę "Administrator"', correct: false },
      {
        text: 'część względna identyfikatora tego konta ma stałą wartość 500',
        correct: true,
      },
      {
        text: 'część względna identyfikatora tego konta ma stałą wartość 0',
        correct: false,
      },
    ],
  },
  {
    text: '279. Co oznacza termin "asocjacja bezpieczeństwa" (ang.Security Association)?',
    answers: [
      {
        text: 'Nazwa jednokierunkowego protokołu uwierzytelniania tuneli IPSec',
        correct: false,
      },
      {
        text: 'Jest to zestaw parametrów zabezpieczonego połączenia niezbędny do poprawnej interpretacji danych płynących w tunelu VPN',
        correct: true,
      },
      {
        text: 'Jest to wstępny proces zestawiania tunelu VPN, w którym negocjowane są parametry połączenia',
        correct: false,
      },
      {
        text: 'Jest to nazwa polityki IPsec określające filtry pakietów poddawanych zabezpieczaniu',
        correct: false,
      },
    ],
  },
  {
    text: '280. Które stwierdzenia dotyczące blokady konta w systemie Windows są nieprawdziwe:',
    answers: [
      {
        text: 'próg blokady określa ilość kolejnych niepomyślnych prób logowania, po osiągnięciu której dostęp do konta będzie czasowo zablokowany',
        correct: true,
      },
      {
        text: 'licznik prób logowania jest zerowany automatycznie po upływie czasu blokady konta',
        correct: false,
      },
      {
        text: 'podczas blokady konta, kolejne logowanie będzie możliwe dopiero po wyzerowaniu licznika prób (np. przez administratora)',
        correct: false,
      },
      {
        text: 'w czasie określonym długością okresu zerowania licznika prób logowania, użytkownik nie może podjąć więcej udanych prób logowania niż określa próg blokady',
        correct: false,
      },
    ],
  },
  {
    text: '281. Zapora sieciowa lokalnego systemu na stanowisku X zablokowała możliwość zdalnego odpytywania o dostępności X przy pomocy narzędzia ping, pozostawiając jednak możliwość zdalnego dostępu do serwera www w tym systemie. Mogła to osiągnąć poprzez:',
    answers: [
      {
        text: 'wyłączenie ruchu IP na wszystkich interfejsach, ale pozostawienie dostępu do wskazanych portów TCP',
        correct: false,
      },
      {
        text: 'zablokowanie komunikacji z siecią dla programu ping',
        correct: false,
      },
      {
        text: 'wyłączenie obsługi przychodzących komunikatów ICMP echo',
        correct: true,
      },
      { text: 'odrzucenie całego ruchu ICMP', correct: true },
    ],
  },
  {
    text: '282. Która z poniższych usług aplikacyjnych wykorzystuje mechanizm SSO:',
    answers: [
      { text: 'rlogin', correct: true },
      { text: 'telnet', correct: false },
      { text: 'tcpd', correct: false },
      { text: 'xinetd', correct: false },
      { text: 'ssh', correct: false },
      { text: 'rsh', correct: true },
    ],
  },
  {
    text: '283. Mechanizm sudo umożliwia:',
    answers: [
      {
        text: 'wskazanie konta, z którego można wykonać polecenie bez pytania o hasło użytkownika przypisanego do pliku programu tego polecenia, pod warunkiem przynależności do grupy przypisanego do tego pliku',
        correct: false,
      },
      {
        text: 'określenie jaki użytkownik może wykonywać konkretne programy z innymi uprawnieniami',
        correct: true,
      },
      {
        text: 'wykonywanie tylko programów należących do użytkownika root z uprawnieniami bieżącego użytkownika',
        correct: false,
      },
      {
        text: 'uruchamianie innych aplikacji wyłącznie z uprawnieniami administratora',
        correct: false,
      },
    ],
  },
  {
    text: '284. Mechanizmem PAM można skonfigurować:',
    answers: [
      {
        text: 'ograniczenia czasowe dostępu do systemu operacyjnego',
        correct: true,
      },
      {
        text: 'ograniczenie maksymalnego ilości procesów jakie może uruchomić użytkownik',
        correct: true,
      },
      { text: 'sposób uwierzytelniania aplikacji', correct: true },
      { text: 'procedurę zmiany danych uwierzytelniających', correct: true },
    ],
  },
  {
    text: '285. Preshared key to:',
    answers: [
      { text: '(wstępny) klucz symetryczny', correct: true },
      {
        text: 'mechanizm pozwalający uwierzytelniać i szyfrować za pomocą jednego klucza',
        correct: false,
      },
      {
        text: 'silny mechanizm uwierzytelniania wykorzystujący generowany losowo po obu stronach klucz',
        correct: false,
      },
      {
        text: 'silny mechanizm szyfrowania wykorzystujący certyfikaty SSL do generacji losowego klucza sesyjnego',
        correct: false,
      },
    ],
  },
  {
    text: '286. Mechanizm User Account Control (UAC) systemu Windows:',
    answers: [
      {
        text: 'blokuje konto po zdefiniowanej wcześniej ilości nieudanych prób logowania',
        correct: false,
      },
      {
        text: 'wprowadza dodatkową formę ochrony konta administracyjnego m.in. przed koniami trojańskimi i złośliwym oprogramowaniem',
        correct: true,
      },
      {
        text: 'pozwala administratorowi chwilowo skorzystać z pełnego tokenu administracyjnego',
        correct: true,
      },
      {
        text: 'wirtualizuje dostęp do newralgicznych komponentów systemu plików',
        correct: true,
      },
    ],
  },
  {
    text: '287. Klucz szyfrowania, którym zaszyfrowana została treść pliku (standardowym mechanizmem EFS z systemu NTFS):',
    answers: [
      { text: 'znajduje się w certyfikacie właściciela pliku', correct: false },
      {
        text: 'znajduje się w certyfikacie każdego agenta DRA w systemie operacyjnym',
        correct: false,
      },
      { text: 'jest zapisany wewnątrz zaszyfrowanego pliku', correct: true },
      {
        text: 'znajduje się w certyfikacie administratora systemu operacyjnego',
        correct: false,
      },
      {
        text: 'jest przechowywany wraz z zaszyfrowanym plikiem',
        correct: true,
      },
    ],
  },
  {
    text: '288. Skuteczna weryfikacja w systemie PGP podpisanego cyfrowo listu przesłanego od użytkownika A do użytkownika B wymaga:',
    answers: [
      { text: 'wykonania podpisu kluczem prywatnym B', correct: false },
      { text: 'wykonania podpisu kluczem prywatnym A', correct: true },
      { text: 'wykonania podpisu kluczem publicznym B', correct: false },
      { text: 'wykonania podpisu kluczem publicznym A', correct: false },
    ],
  },
  {
    text: '289. xinetd to:',
    answers: [
      {
        text: 'moduł jądra Linux, który implementuje kontekstową filtrację pakietów',
        correct: false,
      },
      {
        text: 'prosty mechanizm szyfrowania używany przez zaporę sieciową w systemie Linux',
        correct: false,
      },
      {
        text: 'element systemu operacyjnego Linux, odpowiedzialny za dynamiczne uruchamianie usług sieciowych',
        correct: true,
      },
      {
        text: 'moduł jądra Linux, który limity zasobowe w stosie TCP/IP',
        correct: false,
      },
    ],
  },
  {
    text: '290. Przy kopiowaniu zaszyfrowanego pliku z NTFS na partycję FAT:',
    answers: [
      {
        text: 'plik będzie możliwy do odczytu tylko na systemie, na którym został zaszyfrowany',
        correct: false,
      },
      { text: 'plik zostaje odszyfrowany', correct: true },
      {
        text: 'plik będzie później wymagał ręcznego odszyfrowania',
        correct: false,
      },
      {
        text: 'plik może być skopiowany tylko przez użytkownika "Data Recovery Agent"',
        correct: false,
      },
    ],
  },
  {
    text: '291. Zaznacz poprawne warunki, których spełnienie w systemie plików NTFS pozwoli by użytkownik U należący do grupy G mógł odczytać zawartość pliku P w katalogu K:',
    answers: [
      {
        text: 'U lub G dziedziczą dostęp do odczytu z katalogu K',
        correct: true,
      },
      {
        text: 'U jawnie odebrano prawo odczytu P, ale U dziedziczy to prawo z katalogu K',
        correct: false,
      },
      {
        text: 'U jawnie odebrano prawo odczytu P, ale G dziedziczy to prawo z katalogu K',
        correct: false,
      },
      {
        text: 'U lub G mają jawnie nadane prawo odczytu pliku P',
        correct: true,
      },
      {
        text: 'tylko U ma jawnie nadany dostęp do P i K, G nie nadano żadnych praw ani do K, ani do P',
        correct: true,
      },
      {
        text: 'tylko U dziedziczy dostęp do P i K, G nie dziedziczy żadnych praw ani do K, ani do P',
        correct: true,
      },
    ],
  },
  {
    text: '292. Wskaż to z ustawień parametrów haseł (tylko jedno), które jest najkorzystniejsze dla bezpieczeństwa konta:',
    answers: [
      { text: 'okres ważności hasła: nieskończony', correct: false },
      { text: 'maksymalna długość: 14 znaków', correct: false },
      { text: 'minimalna długość: 10 znaków', correct: true },
      { text: 'odwracalne szyfrowanie haseł: włączone', correct: false },
    ],
  },
  {
    text: '293. getfacl --omit-header test ... Oznacza, że:',
    answers: [
      {
        text: 'grupa "agents" może modyfikować zawartość obiektu test',
        correct: false,
      },
      { text: 'właściciel może tworzyć pliki w katalogu test', correct: true },
      {
        text: 'użytkownik "jbond" może modyfikować zawartość obiektu test',
        correct: false,
      },
      {
        text: 'użytkownik "jbond" może przeglądać listę plików w katalogu test',
        correct: true,
      },
    ],
  },
  {
    text: '294. Stosowany w sieciach VPN preshared key to:',
    answers: [
      {
        text: 'klucz publiczny z predefiniowanego certyfikatu SSL służący do generacji asymetrycznego klucza szyfrowania danych',
        correct: false,
      },
      {
        text: 'statycznie ustalony po obu stronach tunelu klucz symetryczny',
        correct: true,
      },
      {
        text: 'mechanizm uwierzytelniania wykorzystujący generowane losowo po obu stronach wstępne klucze asymetryczne D-H',
        correct: false,
      },
      {
        text: 'mechanizm pozwalający uwierzytelniać strony tunelu',
        correct: false,
      },
    ],
  },
  {
    text: '295. Czego nie można ograniczyć za pomocą komendy ulimit (mechanizmu limitów zasobowych)?',
    answers: [
      { text: 'wielkości pliku zrzutu pamięci', correct: false },
      { text: 'ilości otwartych deskryptorów', correct: false },
      { text: 'ilości tworzonych procesów', correct: false },
      {
        text: 'sumy zajmowanej przestrzeni dyskowej przez pliki',
        correct: true,
      },
      { text: 'ilości zalogowanych równocześnie użytkowników', correct: true },
      {
        text: 'ilości wykorzystanej pamięci operacyjnej przez proces',
        correct: false,
      },
    ],
  },
  {
    text: '296. Asocjacja bezpieczeństwa (ang. Security Association) IPsec w systemie Windows:',
    answers: [
      {
        text: 'to protokół zestawiania tunelu IPsec, w którym negocjowane są parametry tunelu',
        correct: false,
      },
      {
        text: 'może być monitorowana przez systemową zaporę sieciową',
        correct: true,
      },
      {
        text: 'obejmuje zestaw parametrów niezbędnych do komunikacji w tunelu IPsec',
        correct: true,
      },
      {
        text: 'to polityka IPsec określająca filtry pakietów poddawanych tunelowaniu',
        correct: false,
      },
    ],
  },
  {
    text: '297. Mechanizm sudo:',
    answers: [
      {
        text: 'zawsze wymaga podania hasła docelowego użytkownika',
        correct: false,
      },
      {
        text: 'można tak skonfigurować by wymagał podania hasła bieżącego użytkownika',
        correct: true,
      },
      {
        text: 'można tak skonfigurować by nie wymagał podania hasła docelowego użytkownika',
        correct: true,
      },
      {
        text: 'nigdy nie wymaga podania hasła docelowego użytkownika',
        correct: false,
      },
    ],
  },
  {
    text: '298. Szyfrowanie asymetryczne w PGP:',
    answers: [
      {
        text: 'jest wykorzystywane do zaszyfrowania treści wiadomości',
        correct: false,
      },
      {
        text: 'jest wykorzystywane przy podpisywaniu wiadomości',
        correct: true,
      },
      {
        text: 'to uzywanie dwoch matematycznie zaleznych kluczy',
        correct: true,
      },
      {
        text: 'wymaga użycia klucza publicznego nadawcy do rozszyfrowania listu',
        correct: false,
      },
      {
        text: 'wymaga użycia klucza publicznego odbiorcy do zaszyfrowania listu',
        correct: true,
      },
    ],
  },
  {
    text: '299. Wskaż możliwe sposoby uwierzytelniania tunelu IPsec w systemie Windows:',
    answers: [
      { text: 'preshared key', correct: false },
      { text: 'certyfikat X.509', correct: true },
      { text: 'hasło', correct: false },
      { text: 'klucz RSA', correct: false },
    ],
  },
  {
    text: '300. Jak często sudo będzie pytać użytkownika o hasło?',
    answers: [
      { text: 'co określony czas od ostatniego użycia', correct: true },
      { text: 'nigdy, jeśli sudo wykorzystuje SSO', correct: false },
      { text: 'tylko przy pierwszym użyciu po zalogowaniu', correct: false },
      { text: 'za każdym razem, kiedy zostanie wywołane', correct: false },
    ],
  },
  {
    text: '301. Mechanizm POSIX ACL umożliwia:',
    answers: [
      {
        text: 'nadawanie praw do zasobów plikowych poszczególnych użytkownikom i grupom',
        correct: true,
      },
      {
        text: 'odtwarzanie skasowanych plików pod warunkiem posiadania praca C',
        correct: false,
      },
      { text: 'szyfrowania plików metodą symetryczną', correct: false },
      {
        text: 'automatyczne sumowanie uprawnień użytkownika ze wszystkich grup, do których należy',
        correct: false,
      },
    ],
  },
  {
    text: '302. Historia haseł jest przechowywana przez system operacyjny:',
    answers: [
      {
        text: 'aby wykluczyć ponowne użycie tego samego hasła jednorazowego',
        correct: false,
      },
      {
        text: 'aby wykluczyć ustawienie nowego hasła identycznego z jakimkolwiek wcześniej wybranych przez tego samego użytkownika od początku',
        correct: false,
      },
      {
        text: 'w połączeniu z minimalnym okresem ważności hasła, aby wykluczyć zbyt częste wybieranie przez użytkownika tego samego nowego hasła',
        correct: true,
      },
      {
        text: 'aby umożliwić tzw. przypomnienie haseł użytkowników (szczególnie użyteczne w przypadku aplikacji nieobsługujących funkcji jednokierunkowych)',
        correct: false,
      },
    ],
  },
  {
    text: '303. Pojedyncza reguła zapory sieciowej Windows:',
    answers: [
      {
        text: 'może dotyczyć jednocześnie ruchu przychodzącego i wychodzącego',
        correct: false,
      },
      {
        text: 'może dotyczyć wszystkich 3 profili sieciowych jednocześnie',
        correct: true,
      },
      { text: 'może być ustawiona z użyciem polecenia netsh', correct: true },
      { text: 'może dotyczyć tylko wskazanego programu', correct: true },
    ],
  },
  {
    text: '304. Grupa użytkowników w systemie MS Windows o nazwie Użytkownicy uwierzytelnieni:',
    answers: [
      { text: 'jest identyczna z grupą Wszyscy', correct: false },
      { text: 'jest podzbiorem grupy Wszyscy', correct: true },
      { text: 'obejmuje wszystkich użytkowników lokalnych', correct: false },
      { text: 'nie obejmuje konta Gość', correct: true },
    ],
  },
  {
    text: '305. Mechanizm mandatory Integrity Control (MIC) system Windows:',
    answers: [
      {
        text: 'przypisuje procesowi jeden z 5 poziomów uprawnień uwzględnianych dodatkowo w kontroli dostępu',
        correct: true,
      },
      {
        text: 'pozwala ograniczyć dostęp do odczytu dla wybranych plików',
        correct: false,
      },
      {
        text: 'pozwala ograniczyć dostęp do zapisu w systemie plików',
        correct: true,
      },
      {
        text: 'pozwala ograniczyć swobodę komunikacji między procesami',
        correct: true,
      },
    ],
  },
  {
    text: '306. Wskaż pliki zaangażowane w konfigurację TCP wrappera w systemie Unix:',
    answers: [
      { text: '/etc/hosts.allow', correct: true },
      { text: '/etc/hosts', correct: false },
      { text: '/etc/hosts.deny', correct: true },
      { text: '/etc/hosts.equiv', correct: false },
    ],
  },
  {
    text: '307. Wybierz prawdziwą kolejność operacji NAT:',
    answers: [
      {
        text: 'PREROUTING(mangle) PREROUTING(nat) FILTERING POSTROUTING(nat) POSTROUTING(mangle)',
        correct: false,
      },
      {
        text: 'PREROUTING(nat) PREROUTING(mangle) FILTERING POSTROUTING(nat) POSTROUTING(mangle)',
        correct: false,
      },
      {
        text: 'PREROUTING(nat) PREROUTING(mangle) FILTERING POSTROUTING(mangle) POSTROUTING(nat)',
        correct: false,
      },
      {
        text: 'PREROUTING(mangle) PREROUTING(nat) FILTERING POSTROUTING(mangle) POSTROUTING(nat)',
        correct: true,
      },
    ],
  },
  {
    text: '308. Wskaż różnicę między dwoma komendami sudo su oraz su:',
    answers: [
      {
        text: 'jedyną różnicą jest to, że aby wykonać polecenie sudo su użytkownik musi należeć do grupy whels',
        correct: false,
      },
      {
        text: "sudo su może wymagać podania hasła bieżącego użytkownika, su natomiast root'a",
        correct: true,
      },
      {
        text: "su będzie wymagać podania hasła bieżącego użytkownika, sudo su natomiast root'a",
        correct: false,
      },
      {
        text: 'nie ma żadnej różnicy, sudo su jest aliasem na su OpenVPN',
        correct: false,
      },
    ],
  },
  {
    text: '309. Które konfiguracje tuneli obsługuje system OpenVPN:',
    answers: [
      {
        text: '1 do wielu przy uwierzytelnianiu poprzez wspólny klucz',
        correct: false,
      },
      {
        text: '1 do 1 przy uwierzytelnianiu poprzez certyfikaty X.509',
        correct: true,
      },
      {
        text: '1 do 1 przy uwierzytelnianiu poprzez wspólny klucz',
        correct: true,
      },
      {
        text: '1 do wielu przy uwierzytelnianiu poprzez certyfikaty X.509',
        correct: true,
      },
    ],
  },
  {
    text: '310. Wskaż elementy konfiguracji klienta ssh niezbędne do uwierzytelnienia bez konieczności interakcji z użytkownikiem:',
    answers: [
      {
        text: 'klucz publiczny użytkownika musi zostać dopisany do pliku authorized_keys w węźle docelowym',
        correct: true,
      },
      {
        text: 'klucz prywatny użytkownika musi zostać dopisany do pliku authorized_keys w węźle docelowym',
        correct: false,
      },
      {
        text: 'w lokalnym pliku known_hosts zapisany musi być klucz publiczny docelowego węzła',
        correct: false,
      },
      {
        text: 'w lokalnym katalogu .ssh znajdować się musi klucz prywatny docelowego węzła',
        correct: false,
      },
    ],
  },
  {
    text: '311. Definicji zaufania (single-sign-on) dla usług r* mbożna dokonywać w:',
    answers: [
      { text: '~/.rhosts', correct: true },
      { text: '/etc/rhosts', correct: false },
      { text: '~/.sso_hosts', correct: false },
      { text: '/etc/hosts.allow', correct: false },
      { text: '/etc/hosts.equiv', correct: true },
      { text: '/etc/hosts', correct: false },
    ],
  },
  {
    text: '312. W jaki sposób przebiega uwierzytelnianie w usłudze rlogin:',
    answers: [
      {
        text: 'uwierzytelnienie obu stron połączenia następuje mechanizmem Challenge-Response',
        correct: false,
      },
      {
        text: 'zawsze wymagane jest uwierzytelnianie bez hasła',
        correct: false,
      },
      {
        text: 'możliwe jest wykorzystanie SSO by nie podawać hasła',
        correct: true,
      },
      { text: 'zawsze wymagane jest hasło', correct: false },
    ],
  },
  {
    text: '313. Udział C$ jest to:',
    answers: [
      {
        text: 'udział domyślny kontrolera domeny służący do obsługi logowania w sieci',
        correct: false,
      },
      {
        text: 'udział służący do dostępu do dysku C w celach zdalnej administracji',
        correct: true,
      },
      {
        text: 'udział komunikacji międzyprocesowej w systemie operacyjnym',
        correct: false,
      },
      { text: 'udział do komunikacji IPsec', correct: false },
    ],
  },
  {
    text: '314. Jaka jest kolejność sprawdzania reguł w plikach hosts.deny hosts.allow:',
    answers: [
      {
        text: 'jeśli znajdzie się najpierw dopasowanie w deny to allow w ogóle nie jest sprawdzane',
        correct: false,
      },
      { text: 'najpierw deny do pierwszego dopasowania', correct: false },
      { text: 'najpierw allow do pierwszego dopasowania', correct: true },
      {
        text: 'jeśli znajdzie się najpierw dopasowanie w allow to deny w ogóle nie jest sprawdzane',
        correct: true,
      },
    ],
  },
  {
    text: '315. Co można ustawić w zasadach kont w MS Windows:',
    answers: [
      { text: 'minimalną długość nazwy użytkownika', correct: false },
      { text: 'maksymalną długość nazwy użytkownika', correct: false },
      { text: 'minimalną długość hasła', correct: true },
      { text: 'maksymalną długość hasła', correct: false },
      { text: 'złożoność hasła', correct: true },
      { text: 'szyfrowanie AES', correct: false },
      { text: 'Minimalny czas ważności hasła', correct: true },
    ],
  },
  {
    text: '316. Czy maska uprawnień POSIX ACL jest definiowana dla każdego użytkownika osobno?',
    answers: [
      {
        text: 'tak, z priorytetem maski domyślnej (logiczny AND)',
        correct: false,
      },
      {
        text: 'nie, maskę można zdefiniować tylko dla grup użytkowników',
        correct: false,
      },
      { text: 'tak, jeśli jawnie wskażemy nazwę użytkownika', correct: false },
      { text: 'nie, istnieje tylko jedna obowiązująca maska', correct: true },
    ],
  },
  {
    text: '317. Przesłanie i zweryfikowanie podpisanego cyfrowo listu w standardzie S/MIME od użytkownika A do użytkownika B wymaga:',
    answers: [
      {
        text: 'pozyskania przez użytkownika B tajnego klucza symetrycznego od A',
        correct: false,
      },
      {
        text: 'pozyskania przez B certyfikatu klucza publicznego A',
        correct: true,
      },
      {
        text: 'pozyskania certyfikatów kluczy publicznych wzajemnie przez obu użytkowników',
        correct: false,
      },
      {
        text: 'pozyskania przez A certyfikatu klucza publicznego B',
        correct: false,
      },
    ],
  },
  {
    text: '318. Szyfrowanie symetryczne plików mechanizmem EFS systemu NTFS:',
    answers: [
      {
        text: 'może być realizowane po zainstalowaniu dodatkowego oprogramowania DRA',
        correct: false,
      },
      {
        text: 'może być realizowane pod warunkiem posiadania przez użytkownika certyfikatu klucza publicznego',
        correct: true,
      },
      {
        text: 'szyfruje pliki użytkownika jego kluczem prywatnym',
        correct: false,
      },
      {
        text: 'nie jest realizowane przez system operacyjny starszy niż Windows 10',
        correct: false,
      },
    ],
  },
  {
    text: '319. Mechanizm impersonation systemu Windows:',
    answers: [
      {
        text: 'jest wykorzystywany przez polecenie <code>runas</code>',
        correct: true,
      },
      {
        text: 'pozwala zdefiniować dla użytkownika inną nazwę wyświetlaną (np. imię i nazwisko) niż nazwę konta',
        correct: false,
      },
      {
        text: 'definiuje 5 dodatkowych poziomów kontroli dostępu do danych i procesów',
        correct: false,
      },
      {
        text: 'pozwala procesowi użyć chwilowo innego niż bieżący tokenu zabezpieczeń',
        correct: true,
      },
    ],
  },
  {
    text: '320. Możliwości uwierzytelniania się przy użyciu SSH2 to:',
    answers: [
      { text: 'mechanizm zaufania (.rhosts)', correct: false },
      { text: 'symetryczne klucze użytkownika', correct: false },
      { text: 'hasło użytkownika', correct: true },
      { text: 'asymetryczne klucze użytkownika', correct: true },
    ],
  },
  {
    text: '321. W jakim celu można weksportować certyfikat do formatu PKCS #12:',
    answers: [
      {
        text: 'W celu wyekstraktowania klucza do szyfrowania wiadomości',
        correct: false,
      },
      {
        text: 'W celu wyekstraktowania klucza aby przekazać go drugiej stronie',
        correct: false,
      },
      { text: 'W celu stworzenia kopii zapasowej certyfikatu', correct: true },
      { text: 'zaimportować w kliencie pocztowym', correct: true },
    ],
  },
  {
    text: '322. Który mechanizm pozwala na wirtualizację jądra systemu:',
    answers: [
      { text: 'VBS', correct: true },
      { text: 'ARM TrustZone', correct: false },
      { text: 'TEE', correct: false },
      { text: 'SSL', correct: false },
    ],
  },
  {
    text: '323. Aby zweryfikować podpis cyfrowy w systemie PGP wiadomości od nadawcy A do odbiorcy B potrzeba:',
    answers: [
      { text: 'klucz prywatny nadawcy A', correct: false },
      { text: 'klucz publiczny nadawcy A', correct: true },
      { text: 'klucz prywatny odbiorcy B', correct: false },
      { text: 'klucz publiczny odbiorcy B', correct: false },
    ],
  },
  {
    text: '324. Kiedy w Windowsie następuje zerowanie licznika prób wpisania hasła:',
    answers: [
      { text: 'Po pomyślnym zalogowaniu', correct: true },
      { text: 'Po upływie określonego czasu', correct: true },
      { text: 'Administrator może ręcznie wyzerować', correct: true },
      { text: 'nie pamiętam, ale nie powinno być zaznaczone', correct: false },
    ],
  },
  {
    text: '325. Czy iptables umożliwia określenie domyślnej polityki w łańcuchu?',
    answers: [
      { text: 'Tylko w łańcuchach tablicy filter', correct: false },
      { text: 'Tylko w predefiniowanych łańcuchach', correct: true },
      { text: 'Tak, w każdym łańcuchu', correct: false },
      { text: 'tylko w nowo utworzonych lancuchach', correct: false },
      { text: 'tak', correct: false },
      { text: 'tylko w standardowych lancuchach', correct: true },
      { text: 'Nie', correct: false },
    ],
  },
  {
    text: '326. W metodzie uzgadniania klucza Diffiego-Hellmana system kompromituje (narusza bezpieczenstwo):',
    answers: [
      { text: 'przechwycenia jednego z wymienianych kluczy', correct: false },
      { text: 'przechwycenia obu wymienianych kluczy', correct: false },
      {
        text: 'podstawienie falszywego klucza w miejsce kazdego z wymienianych',
        correct: false,
      },
      {
        text: 'podstawienie falszywego klucza w miejsce dowolnego z wymienianych',
        correct: true,
      },
    ],
  },
  {
    text: '327. Klasa B1 wg TCSEC ("Orange Book") lub rownowazna jej klasa EAL4 wg Common Criteria wymaga m. in.:',
    answers: [
      { text: 'ochrony systemowych obszarow pamieci', correct: true },
      { text: 'uwierzytelniania uzytkownikow', correct: true },
      { text: 'scislej kontroli dostepu do danych (MAC)', correct: true },
      { text: 'szyfrowania plikow', correct: false },
    ],
  },
  {
    text: '328. Czy certyfikaty SSL dla obu stron polaczenia vpn nawiazanego przy pomocy programu OpenVPN musza by podpisane przez ta sam zaufana strone trzecia?',
    answers: [
      { text: 'nie, poniewaz nie ma takiej opcji w OpenVPN', correct: false },
      {
        text: 'nie, poniewaz nie ma znaczenia czy to jest to samo CA, wazne aby zaufanie strony trzeciej bylo ogolnie znane CA, np. Thawte, VeriSign, Unizeto',
        correct: false,
      },
      {
        text: 'nie trzeba podawac parametru wskazujacego na CA, jest to opcjonalne',
        correct: false,
      },
      { text: 'tak', correct: true },
    ],
  },
  {
    text: '329. Ktore funkcje i parametry konfiguracyjne PHP moga byc wykorzystane do ochrony przed atakami typu command injection?',
    answers: [
      { text: 'magic_quotes_gpc', correct: true },
      { text: 'addslashes()', correct: true },
      { text: 'mysql_escape_string()', correct: false },
      { text: 'strip_tags()', correct: false },
    ],
  },
  {
    text: '330. Wskaz prawidlowe stwierdzenia dotyczace metod uwierzytelniania systemow operacyjnych MS Windows w srodowisku sieciowym:',
    answers: [
      { text: 'Kerberos jest bezpieczniejszy niz LM i NTLM', correct: true },
      { text: 'LM jest bezpieczniejszy niz NTLM', correct: false },
      {
        text: 'Kerberos jest bezpieczniejszy niz NTLM, ale jest dostepny tylko w srodowisku domenowym',
        correct: true,
      },
      { text: 'NTLM jest bezpieczniejszy niz LM', correct: true },
    ],
  },
  {
    text: '331. Czy program inetd to:',
    answers: [
      {
        text: 'jest waznym elementem systemu operacyjnego Linux, odpowiedzialny za uruchamianie innych programow',
        correct: true,
      },
      {
        text: 'krytyczny program w systemie operacyjnym Linux, ktory zawsze musi byc uruchomiony',
        correct: false,
      },
      {
        text: 'krytyczny program w systemie operacyjnym Linux, ktory zawsze musi byc uruchomiony, jest rodzicem dla wszystkich nowo powstalych procesow',
        correct: false,
      },
      {
        text: 'bardzo wazny komponent systemu Linux, bez ktorego system operacyjny nie bedzie dzialal prawidlowo z uwagi na niemoznosc uruchamiania dodatkowych programow',
        correct: false,
      },
    ],
  },
  {
    text: '332. Wskaz cechy mechanizmu SYN cookies:',
    answers: [
      {
        text: 'pozwala przegladarce na bezpieczna aktualizacje ciasteczek',
        correct: false,
      },
      {
        text: 'minimalizuje ilosc informacji potrzebnych przegladarce do uwierzytelniania zdalnego dostepu',
        correct: false,
      },
      {
        text: 'identyfikuje polaczenie wartoscia wpisywana do pola ACK',
        correct: true,
      },
      {
        text: 'minimalizuje wielkosc zasobow przydzielanych przy odbiorze zadania nawiazania polaczenia',
        correct: true,
      },
    ],
  },
  {
    text: '333. Jesli ls -l plik.txt wyglada nastepujaco -rwxr-xr-x+ 1 user group 1000 2005-01-10 09:00 plik.txt to chmod 715 plik.txt spowoduje:',
    answers: [
      { text: "zwiekszenie uprawnien wpisom ACL'owym", correct: false },
      {
        text: 'zmiane uprawnien grupie "group" dla tego pliku',
        correct: false,
      },
      { text: "zmniejszenie uprawnien wpisom ACL'owym", correct: true },
      { text: 'rozszerzenie uprawnien dla innych', correct: false },
    ],
  },
  {
    text: '334. Zapora sieciowa wbudowana w Ms Win XP sp2:',
    answers: [
      { text: 'jest typu stateless', correct: false },
      {
        text: 'jest jedyna mozliwa do zastosowania zapora sieciowa w systemie',
        correct: false,
      },
      {
        text: 'pozwala powiadamiac uzytkownika droga mailowa o zagrozeniach',
        correct: false,
      },
      { text: 'jest zapora typu stateful', correct: true },
    ],
  },
  {
    text: '335. W jaki sposob mozna utworzyc wiele polaczen z danego hosta za pomoca programu OpenVPN?',
    answers: [
      {
        text: 'nalezy powtorzyc wpisanie opcji: remote tyle razy ile polaczen VPN mamy utworzyc',
        correct: false,
      },
      {
        text: 'nalezy uruchomic program OpenVPN z przelacznikiem: --force-multi-instance',
        correct: false,
      },
      { text: 'nie ma takiej mozliwosci', correct: false },
      {
        text: 'nalezy uruchomic program OpenVPN z wieloma plikami konfiguracyjnymi, kazdy plik definiuje jedno polaczenie',
        correct: true,
      },
      {
        text: 'nalezy wykorzystac opcje --mode server ale tylko dla polaczen z zastosowaniem certyfikatow SSL',
        correct: false,
      },
      {
        text: 'nalezy uruchomic kolejne instancje programu OpenVPN wraz z osobnymi plikami konfiguracyjnymi',
        correct: true,
      },
    ],
  },
  {
    text: '336. Ktore polecenie bedzie poprawne, dla ustalenia DNAT?',
    answers: [
      {
        text: 'iptables -t nat -A FORWARD -d 150.254.17.3 -i eth- -j DNAT --to 192.168.1.1',
        correct: false,
      },
      {
        text: 'iptables -t nat -A PREROUTING -d 150.254.17.3 -i eth0 -j NAT --to 192.168.1.1',
        correct: false,
      },
      {
        text: 'iptables -t nat -A PREROUTING -i eth0 -j SAME --to 150.254.17.2',
        correct: false,
      },
      {
        text: 'iptables -t nat -A PREROUTING -d 150.254.17.3 -i eth0 -j DNAT --to 192.168.1.1',
        correct: true,
      },
      {
        text: 'iptables -t nat -A POSTROUTING -d 150.254.17.3 -i eth0 -j DNAT --to 192.168.1.1',
        correct: false,
      },
      {
        text: 'iptables -t nat -A POSTROUTING -o eth0 -j SAME --to 150.254.17.2',
        correct: true,
      },
    ],
  },
  {
    text: '337. Ponizsza regula zostala wpisana na komputerze pelniacym role routera: iptables -t filter -A INPUT -m state --state NEW -j DROP',
    answers: [
      { text: 'odrzuca nowe polaczenia do tego komputera', correct: true },
      {
        text: 'odrzuca nowe polaczenia inicjalizowane przez ten komputer',
        correct: false,
      },
      {
        text: 'odrzuca nowe polaczenia przechodzace przez ten komputer',
        correct: false,
      },
      {
        text: 'DROP znaczy nie przeszukuj dalej zapory, przepusc pakiet',
        correct: false,
      },
    ],
  },
  {
    text: '338. Narzedzie OpenVPN:',
    answers: [
      { text: 'dziala tylko na protokole TCP', correct: false },
      {
        text: 'wykorzystuje mechanizm pre-shared key do losowego generowania kluczy',
        correct: false,
      },
      {
        text: 'nie ma wyroznionego programu serwerowego i klienckiego',
        correct: true,
      },
      { text: 'jest przykladem SSL-VPN', correct: true },
      {
        text: 'wykorzystuje certyfikaty MD5 i funkcje skrotu SHA-1 do uwierzytelniania stron i szyfrowania ruchu sieciowego',
        correct: false,
      },
      {
        text: 'wykorzystuje mechanizm SSL-VPN do laczenia sie z serwerami wspierajacymi protokol https np. Apache',
        correct: false,
      },
    ],
  },
  {
    text: '339. Narzedzie Vtun to:',
    answers: [
      {
        text: 'samodzielny pakiet niskopoziomowego dzialajacego na poziomie jadra oprogramowania do tworzenia podsieci VPN',
        correct: false,
      },
      {
        text: 'proste narzedzie do tworzenia polaczen VPN korzystajace tylko z jednego pliku konfiguracyjnego i zestawu narzedzi obecnych w systemie',
        correct: true,
      },
      {
        text: 'narzedzie dzialajace na poziomie warstwy uzytkownika pozwalajace tworzyc tylko pojedyncze polaczenia VPN przy uzyciu prostego pliku konfiguracyjnego vtund',
        correct: false,
      },
    ],
  },
  {
    text: '340. Program Vtun dziala w architekturze:',
    answers: [
      { text: 'punkt – punkt', correct: false },
      { text: 'klient – serwer', correct: true },
      {
        text: 'polaczenia peer-to-peer dla kazdego polaczenia',
        correct: false,
      },
      {
        text: 'w zadnej z powyzszych poniewaz Vtun jest bardzo prosty i nie zawiera w sobie zadnej skomplikowanej architektury',
        correct: false,
      },
    ],
  },
  {
    text: '341. Program Vtun dziala:',
    answers: [
      { text: 'na porcie domyslnym 1045 ale mozna to zmienic', correct: false },
      {
        text: 'na porcie domyslnym 5000 i mozna to zmienic ale trzeba przekompilowac kod programu',
        correct: false,
      },
      { text: 'na domyslnym porcie 5000', correct: true },
      {
        text: 'na porcie domyslnym 1001 mozna to zmienic w pliku konfiguracyjnym vtund.conf',
        correct: false,
      },
      {
        text: 'na porcie domyslnym 1045 ale mozna to bez problemu zmienic w pliku konfiguracyjnym vtund.conf',
        correct: false,
      },
    ],
  },
  {
    text: '342. Polaczenie w Vtun przebiega nastepujaco:',
    answers: [
      {
        text: 'w momencie tworzenia polaczenia wykonywane sa odpowiednie podsekcje up w definicji danego polaczenia ktore ma zostac utworzone, w momencie zakonczenia polaczenia wykonywana jest podsekcja down w definicji polaczenia',
        correct: true,
      },
      {
        text: 'po nawiazaniu polaczenia obie strony uzgadniaja parametry polaczenia takie jak np. haslo i rodzaj transmisji danych, w momencie zakonczenia polaczenia nastepuje specjalna procedura rozpoczynana przez strone, ktora chce zakonczyc polaczenie',
        correct: false,
      },
      {
        text: 'w zaden z wymienionych, na poczatku sposobow, obie strony musza wymienic sie ustalonym haslem, potwierdzic jego prawdziwosc, wynegocjowac parametry transmisji i dopiero tworzone jest polaczenie do przesylania danych, zakonczenie rozpoczynane jest przez dowolna strone',
        correct: false,
      },
    ],
  },
  {
    text: '343. Czy polecenie jest poprawne? iptables -t mangle -A PREROUTING -s localnet -d ! localnet -m ipp2p --dc -m comment --comment "zla regulka" -j TTL --ttl-set 1',
    answers: [
      { text: 'tak, ale system bedzie usuwal te pakiety', correct: true },
      {
        text: 'tak, lecz taka regula niczego nie zmieni, gdyz nie ma celu ACCEPT lub DROP',
        correct: false,
      },
      {
        text: 'nie, gdyz nie mozna uzywac wielu argumentow " -m"',
        correct: false,
      },
      {
        text: 'nie, gdyz cel TTL moze byc uzywany tylko w lancuchu POSTROUTING',
        correct: false,
      },
    ],
  },
  {
    text: '344. Idea polaczen typu VPN jest:',
    answers: [
      {
        text: 'zmiana routingu pakietow, aby z jednej sieci pakiety trafialy bezposrednio do sieci docelowej',
        correct: false,
      },
      {
        text: 'wsparcie polaczen p2p, aby hosty mogly bezposrednio komunikowal sie',
        correct: false,
      },
      {
        text: 'obejscie problemow z polaczeniami z sieciami zlokalizowanymi za NAT',
        correct: false,
      },
      {
        text: 'mozliwosc zapewnienia bardziej niezawodnych, w sensie polaczeniowym, niz TCP polaczen miedzy hostami',
        correct: false,
      },
      {
        text: 'utworzenie sieci laczacej odseparowane, odlegle sieci lokalne',
        correct: true,
      },
    ],
  },
  {
    text: '345. Opcja PARANOID w pliku hosts.deny:',
    answers: [
      {
        text: 'blokuje zdalne zarzadzanie mechanizmem TCP wrappers, pozostawiajac dostep tylko z lokalnego hosta',
        correct: false,
      },
      {
        text: 'wymusza sprawdzanie segmentow TCP czy sa poprawne w stosunku do norm RFC',
        correct: false,
      },
      {
        text: 'pozwala ograniczyc ilosc pakietow/s przychodzacych do danej uslugi',
        correct: false,
      },
      {
        text: 'blokuje pakiety pochodzace od hosta, ktorego ip nie posiada nazwy domenowej',
        correct: true,
      },
    ],
  },
  {
    text: '346. getfacl --omit-header acl-test5 user::r-x user:inf44444:r-- group::rw- group:student:r-x mask::rwx other::--x Oznacza:',
    answers: [
      {
        text: 'uzytkownik "inf44444" nie moze czytac pliku acl-test5',
        correct: false,
      },
      {
        text: 'wlasciciel ma prawo zmodyfikowac zawartosc katalogu acl-test5',
        correct: false,
      },
      {
        text: 'uzytkownik "inf44444" moze czytac plik acl-test5',
        correct: true,
      },
      {
        text: 'maska blokuje wszystkie uprawnienia do pliku acl-test5',
        correct: false,
      },
      {
        text: 'grupa wlasciciela moze zmodyfikowac plik acl-test5',
        correct: true,
      },
      {
        text: 'grupa "student" moze zmodyfikowac plik acl-test5',
        correct: false,
      },
    ],
  },
  {
    text: '347. Zaleta single-sign-on jest:',
    answers: [
      { text: 'jednokrotne uwierzytelnianie', correct: true },
      {
        text: 'stosowanie funkcji skrotu w celu uwierzytelniania',
        correct: false,
      },
      { text: 'jednokrotne szyfrowanie', correct: false },
      { text: 'jednokrotna autoryzacja', correct: false },
    ],
  },
  {
    text: "348. $ssh host Enter passphrase for key '/home/junior/.ssh/id_dsa': Wpis passphrase to:",
    answers: [
      {
        text: 'Haslo, ktorym jest zaszyfrowany klucz publiczny',
        correct: false,
      },
      { text: 'haslo, ktorym jest zaszyfrowany klucz prywatny', correct: true },
      { text: 'klucz, ktorym bedzie szyfrowana transmisja', correct: false },
      {
        text: 'haslo wymagane przez zdalny host, aby zostac zalogowanym',
        correct: false,
      },
    ],
  },
  {
    text: '349. getfacl --omit-header acl-test1 user::rw- user:junior:rwx group::r-- group:student:r-x mask::r-- other::--- Oznacza, ze:',
    answers: [
      { text: 'wlasciciel moze wykonac plik', correct: false },
      { text: 'grupa domyslna/wlasciciela moze odczytac plik', correct: true },
      { text: 'uzytkownik "junior" moze wykonac plik', correct: false },
      { text: 'wlasciciel moze modyfikowac plik', correct: true },
      { text: 'grupa "student" moze wykonac plik', correct: false },
      { text: 'inni moga zmodyfikowac plik', correct: false },
    ],
  },
  {
    text: '350. Jak zachowa sie system kontroli ACL standardu POSIX w przypadku uzytkownika U nalezacego do grupy G i wpisanego na liscie ACL obiektu p, jesli ani U ani G nie maja jawnie przydzielonego prawa r, ale kategoria "wszyscy uzytkownicy" (others) takie uprawnienie do obiektu posiada:',
    answers: [
      {
        text: 'prawo r do obiektu p zostanie efektywnie przyznane, o ile U jest wlascicielem p',
        correct: false,
      },
      {
        text: 'prawo r do obiektu p zostanie efektywnie przyznane bezwarunkowo',
        correct: false,
      },
      {
        text: 'prawo r do obiektu p nie zostanie efektywnie przyznane',
        correct: true,
      },
      {
        text: 'prawo r do obiektu p nie zostanie efektywnie przyznane, ale U odziedziczy je w glab, jesli p jest katalogiem',
        correct: false,
      },
    ],
  },
  {
    text: '351. Szyfr, w ktorym poddawana szyfrowaniu zostaje tej samej wielkosci jednobajtowa porcja nieregularnie pojawiajacych sie danych, nazywamy:',
    answers: [
      { text: 'strumieniowym', correct: true },
      { text: 'symetrycznym', correct: false },
      { text: 'blokowym', correct: false },
      { text: 'niesymetrycznym', correct: false },
    ],
  },
  {
    text: '352. SUID to:',
    answers: [
      { text: 'uproszczona wersji limitow', correct: false },
      { text: 'bit uprawnien', correct: true },
      { text: 'odpowiednik SGID dla katalogow', correct: false },
      { text: 'rozszerzenie mechanizmu SUDO', correct: false },
    ],
  },
  {
    text: '353. W jaki sposob administrator moze narzucic ograniczenia uzytkownikom (limity)?',
    answers: [
      { text: 'korzystajac z mechanizmu PAM', correct: true },
      { text: 'korzystajac z mechanizmu Kerberos', correct: false },
      { text: 'wykorzystujac skrypt "hosts.equiv"', correct: false },
      { text: 'wykorzystujac skrypty startowe systemu', correct: false },
    ],
  },
  {
    text: '354. Problem przepelnienia bufora dotyczy potencjalnie aplikacji:',
    answers: [
      { text: 'napisanych w jezyku C', correct: true },
      { text: 'napisanych w jezyku Java', correct: false },
      { text: 'uruchamianych w systemie z rodziny Windows', correct: true },
      { text: 'uruchamianych w systemie z rodziny Unix/Linux', correct: true },
    ],
  },
  {
    text: '355. Czy istnieje mozliwosc zmiany portu docelowego i adresu docelowego na adres localhost i dowolny inny port?',
    answers: [
      { text: 'tak', correct: false },
      {
        text: 'tylko, jesli okreslimy protokol oraz oryginalny port docelowy',
        correct: true,
      },
      { text: 'tylko poprzez dodatkowy modul', correct: false },
      { text: 'nie', correct: false },
    ],
  },
  {
    text: '356. W jaki sposob program OpenVPN bedzie wiedzial, gdzie znajduje sie drugi koniec tunelu VPN:',
    answers: [
      {
        text: 'OpenVPN w sposob interaktywny poprosi uzytkownika o podanie adresu IP i numeru portu',
        correct: false,
      },
      {
        text: 'nalezy wpisac odpowiednia opcje w pliku konfiguracyjnym',
        correct: true,
      },
      {
        text: 'OpenVPN wysle zapytanie do najblizszego serwera VPN',
        correct: false,
      },
      {
        text: 'OpenVPN odczytuje zawartosc zdalnej tablicy routingu i pobiera ta informacje',
        correct: false,
      },
    ],
  },
  {
    text: '357. Dyrektywa "mask" w ACL okresla:',
    answers: [
      { text: 'mozna ja modyfikowac jedynie raz', correct: false },
      { text: 'jest utozsamiana z uprawnieniami grupy', correct: true },
      {
        text: 'ukrywanie nadanych uprawnien dodatkowych uzytkownikow',
        correct: false,
      },
      { text: 'nie ma zadnego znaczenia', correct: false },
    ],
  },
  {
    text: '358. Opcja spawn w pliku hosts.deny:',
    answers: [
      { text: 'pozwala tworzyc kolejne procesy TCP wrapper', correct: false },
      { text: 'jest wykorzystywana tylko w pliku hosts.allow', correct: false },
      { text: 'nie jest wykorzystywana', correct: false },
      {
        text: 'pozwala odeslac do nadawcy specjalnie spreparowana wiadomosc w odpowiedzi na zadanie',
        correct: true,
      },
    ],
  },
  {
    text: '359. Ktore polecenie bedzie poprawne, dla ustalenia SNAT:',
    answers: [
      {
        text: 'iptables -t nat -A FORWARD -o eth0 -j SNAT --to 150.254.17.2',
        correct: false,
      },
      {
        text: 'iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 150.254.17.2',
        correct: true,
      },
      {
        text: 'iptables -t nat -A PREROUTING -o eth0 -j SAME --to 150.254.17.2',
        correct: false,
      },
      {
        text: 'iptables -t nat -A POSTROUTING -o eth0 -j NAT --to 150.254.17.2',
        correct: false,
      },
      {
        text: 'iptables -t fnat -A PREROUTING -o eth0 -j SNAT --to 150.254.17.2',
        correct: false,
      },
      {
        text: 'iptables -t nat -A POSTROUTING -o eth0 -j SAME --to 150.254.17.2',
        correct: false,
      },
    ],
  },
  {
    text: '360. Czy iptables umozliwia ograniczenie dostepu do uslugi w jednym poleceniu?',
    answers: [
      { text: 'jesli okreslamy protokol', correct: false },
      { text: 'jesli nie okreslimy protokolu', correct: false },
      { text: 'nie', correct: false },
      { text: 'tak', correct: true },
    ],
  },
  {
    text: '361. Oprogramowanie OpenVPN wykorzystuje tablice routingu w Linuxie:',
    answers: [
      {
        text: 'do sprawdzenia kosztu trasy prowadzacej do sieci po drugiej stronie polaczenia VPN',
        correct: false,
      },
      {
        text: 'aby dowiedziec sie jak nawiazac polaczenie z siecia po drugiej stronie tunelu VPN',
        correct: false,
      },
      {
        text: 'do przechowywania trasy do sieci dostepnej po drugiej stronie polaczenia VPN',
        correct: true,
      },
      {
        text: 'jako bufor przechowujacy nadchodzace informacje o zmianie trasy do odleglej sieci po drugiej stronie polaczenia VPN',
        correct: false,
      },
    ],
  },
  {
    text: '362. Nazwa konta "administrator" w systemie Ms Windows XP:',
    answers: [
      { text: 'mozna ja zmienic w kazdej chwili', correct: true },
      { text: 'jest definiowana przy instalacji systemu', correct: false },
      {
        text: 'mozna ja zmienic tylko przy wykorzystaniu dodatkowego oprogramowania',
        correct: false,
      },
      { text: 'jest stala i nie moze byc zmieniona', correct: false },
    ],
  },
  {
    text: '363. Jaki uzytkownik zostanie wybrany w momencie logowania sie na zdalna maszyne przez rsh, gdy w poleceniu rsh nie podano nazwy uzytkownika?:',
    answers: [
      {
        text: 'wystapi blad podczas uwierzytelniania poniewaz nie podano nazwy uzytkownika',
        correct: false,
      },
      { text: 'lokalny uzytkownik nobody', correct: false },
      {
        text: 'zawsze root z uwagi na mozliwosc wykonania niektorych komend systemowych',
        correct: false,
      },
      { text: 'lokalny uzytkownik rshd', correct: false },
      { text: 'zdalny uzytkownik rshd', correct: false },
      { text: 'lokalny uzytkownik operator', correct: false },
      { text: 'lokalny biezacy uzytkownik', correct: true },
    ],
  },
  {
    text: '364. Do czego sluzy komenda rsh?',
    answers: [
      {
        text: 'pozwala wykonac zdalne polecenie na lokalnym hoscie',
        correct: false,
      },
      { text: 'pozwala wykonac polecenie na zdalnym hoscie', correct: true },
      {
        text: 'pozwala nawiazac szyfrowane polaczenie ze zdalnym hostem',
        correct: false,
      },
    ],
  },
  {
    text: '365. user::rw- user:inf44444:r-x group::rwx group:student:rwx mask::rwx other::--- Oznacza:',
    answers: [
      { text: 'grupa "student" nie moze skasowac pliku', correct: false },
      { text: 'uzytkownik "inf44444" moze wykonac plik', correct: true },
      { text: 'grupa "student" moze skasowac katalog', correct: true },
      { text: 'wlasciciel moze wykonac plik', correct: false },
      { text: 'maska blokuje wszystkie uprawnienia', correct: false },
      {
        text: 'grupa domyslna (wlasciciela) nie moze zmodyfikowac pliku',
        correct: false,
      },
    ],
  },
  {
    text: '366. Czy system MS Windows korzysta z serwera Kerberos?',
    answers: [
      { text: 'nigdy', correct: false },
      { text: 'tylko w starszych systemach (95, 98)', correct: false },
      { text: 'zawsze', correct: false },
      { text: 'jesli zostanie odpowiednio skonfigurowany', correct: true },
    ],
  },
  {
    text: '367. Algorytmy SHA-256 i SHA-512 roznia sie wzajemnie:',
    answers: [
      { text: 'ograniczeniami eksportowymi', correct: false },
      { text: 'dlugoscia kluczy', correct: false },
      { text: 'wielkoscia wynikowego skrotu', correct: true },
      { text: 'zadne z powyzszych', correct: false },
    ],
  },
  {
    text: '368. Ktorym z ponizszych terminow okresla sie ograniczone srodowisko wykonawcze aplikacji lub jej komponentu:',
    answers: [
      { text: 'komnata (room)', correct: false },
      { text: 'komora (chamber)', correct: false },
      { text: 'karcer (jailbox)', correct: false },
      { text: 'piaskownica (sandbox)', correct: true },
    ],
  },
  {
    text: '369. Kontrola dostepu do zasobow jest zwiazana z zachowaniem wlasnosci:',
    answers: [
      { text: 'poufnosci i integralnosci', correct: true },
      { text: 'tylko poufnosci', correct: false },
      { text: 'tylko integralnosci', correct: false },
      { text: 'zadnej z powyzszych', correct: false },
    ],
  },
  {
    text: '370. Czy RSBAC to:',
    answers: [
      {
        text: 'poprawnie skonfigurowana polityka bezpieczenstwa',
        correct: false,
      },
      { text: 'domyslne uprawnienia systemowe', correct: false },
      { text: 'zestaw rozszerzajacy kontrole uprawnien', correct: true },
      { text: 'zestaw lat na jadro systemu Linux', correct: false },
    ],
  },
  {
    text: '371. Pre-shared key to:',
    answers: [
      {
        text: 'przestarzaly mechanizm sluzacy do logowania sie na zdalnego hosta bez podawania hasla',
        correct: false,
      },
      { text: 'cos takiego nie istnieje', correct: false },
      {
        text: 'prosty mechanizm pozwalajacy szyfrowac i uwierzytelniac strony za pomoca jednego klucza',
        correct: true,
      },
      {
        text: 'silny mechanizm uwierzytelniania wykorzystujacy generowany losowo po obu stronach klucz',
        correct: false,
      },
      {
        text: 'silny mechanizm szyfrowania wykorzystujacy certyfikaty SSL do generacji losowego klucza sesyjnego',
        correct: false,
      },
      { text: 'jest to przyklad kryptografii symetrycznej', correct: true },
    ],
  },
  {
    text: '372. Co to jest challenge-response?',
    answers: [
      {
        text: 'mechanizm pozwalajacy uwierzytelniac sie bez potrzeby przesylania tajnego klucza',
        correct: true,
      },
      {
        text: 'przestarzala forma uwierzytelniania stosowana w ssh',
        correct: false,
      },
      { text: 'nie istnieje cos takiego', correct: false },
      {
        text: 'mechanizm wykorzystywany w kryptografii dyskretnej',
        correct: false,
      },
      {
        text: 'silny mechanizm szyfrowania wykorzystujacy kryptografie klucza publicznego',
        correct: false,
      },
    ],
  },
  {
    text: '373. Czy serwer KDC w systemie Kerberos przechowuje konta uzytkownikow?',
    answers: [
      { text: 'tak', correct: true },
      { text: 'tylko lokalne konta', correct: false },
      { text: 'nie', correct: false },
      { text: 'tylko konta administratorow', correct: false },
    ],
  },
  {
    text: '374. W jaki sposob polaczenie nawiazane przez rsh jest zabezpieczone?',
    answers: [
      { text: 'kodowana komunikacja przy uzyciu funkcji XOR', correct: false },
      {
        text: 'szyfrowana komunikacja po podaniu hasla i loginu',
        correct: false,
      },
      {
        text: 'komunikacja uwierzytelniana w kryptograficznie bezpieczny sposob',
        correct: false,
      },
      { text: 'komunikacja nie jest chroniona', correct: true },
    ],
  },
  {
    text: '375. W RSBAC, czy mozna zmienic uprawnienia do katalogu dla programu podczas jego dzialania?',
    answers: [
      {
        text: 'jesli program posiada taka mozliwosc (programista uwzglednil taka opcje)',
        correct: false,
      },
      { text: 'nie jest to okreslone', correct: false },
      { text: 'istnieja takie mozliwosci', correct: true },
      { text: 'nie', correct: false },
    ],
  },
  {
    text: '376. Czy TCP wrapper to:',
    answers: [
      {
        text: 'samodzielny program analizujacy tylko polaczenia tcp',
        correct: false,
      },
      {
        text: 'lata (ang. patch) rozszerzajaca funkcjonalnosc programu xinetd',
        correct: false,
      },
      {
        text: 'program analizujacy tylko przychodzace polaczenia tcp, ale dla numerow portow na ktorych uruchomione sa uslugi zarzadzane przez xinetd',
        correct: true,
      },
      {
        text: 'program w postaci prostego firewalla za pomoca ktorego mozna blokowac wychodzace polaczenia, odpowiednie reguly zapisywane sa w plikach /etc/hosts.allow i /etc/hosts.deny',
        correct: false,
      },
      {
        text: 'dodatkowy podsystem sieciowy dla systemu operacyjnego Linux pozwalajacy na nakladanie ograniczen dla polaczen przychodzacych',
        correct: false,
      },
    ],
  },
  {
    text: '377. user::r-x user:inf44444:r-- group::rw- group:student:r-x mask::rwx other::--x Oznacza:',
    answers: [
      { text: 'wszyscy moga wykonac plik', correct: true },
      { text: 'grupa "student" moze zmodyfikowac plik', correct: false },
      { text: 'uzytkownik "inf44444" nie moze czytac plik', correct: false },
      { text: 'uzytkownik "inf44444" moze czytac plik', correct: true },
      { text: 'grupa wlasciciela moze zmodyfikowac plik', correct: true },
      { text: 'maska blokuje wszystkie uprawnienia', correct: false },
    ],
  },
  {
    text: '378. Jaka usluga jest szczegolnie trudna do filtrowania statycznego?',
    answers: [
      {
        text: 'ftp, poniewaz domyslnie serwery dzialaja w trybie pasywnym',
        correct: false,
      },
      {
        text: 'ftp, poniewaz domyslnie serwery dzialaja w trybie aktywnym',
        correct: true,
      },
      { text: 'rlogin, bo costam', correct: false },
      { text: 'rlogin, bo drugie costam', correct: false },
    ],
  },
  {
    text: '379. Certyfikat EFS używany w NTFS zawiera:',
    answers: [
      { text: 'klucz, którym szyfruje się pliki', correct: false },
      { text: 'klucz, którym deszyfruje się pliki', correct: false },
      {
        text: 'klucz publiczny użytkownika, używany do odszyfrowywania kluczy FEK',
        correct: true,
      },
      {
        text: 'klucz publiczny użytkownika, używany do szyfrowania kluczy FEK',
        correct: false,
      },
    ],
  },
  {
    text: '380. Które stwierdzenia dotyczące blokady konta użytkownika w systemie Windows są nieprawdziwe:',
    answers: [
      {
        text: 'licznik prób logowania jest zerowany po każdym nieudanym logowaniu',
        correct: true,
      },
      {
        text: 'licznik prób logowania jest zerowany automatycznie po zadanym czasie',
        correct: false,
      },
      {
        text: 'licznik prób logowania może wyzerować administrator',
        correct: false,
      },
      {
        text: 'licznik prób logowania jest zerowany po każdym pomyślnym zalogowaniu',
        correct: false,
      },
    ],
  },
  {
    text: '381. Zasoby systemu operacyjnego MS Windows udostępnione poprzez SMB:',
    answers: [
      {
        text: 'są dostępne zdalnie tylko dla tych użytkowników, którzy posiadają lokalne konto w systemie operacyjnym',
        correct: false,
      },
      { text: 'nazywa się portami', correct: false },
      {
        text: 'zawsze wymagają uwierzytelniania (podania hasła) przy dostępie zdalnym',
        correct: false,
      },
      {
        text: 'mogą mieć ograniczony dostęp do odczytu i/lub zapisu tylko dla wskazanych użytkowników',
        correct: true,
      },
    ],
  },
  {
    text: '382. Użytkownik U systemu Linux należący do grupy G1 nie ma wpisu na liście ACL do zasobu O w systemie plików. Jednak grupie G1 na liście ACL zasobu O nadano prawa r i x, a uprawnienia domyślne tego zasobu wynoszą rwx. Jakie efektywne uprawnienia do O posiada U? (U nie jest właścicielem O i nie należy do grupy zasobu O, mask=rwx)',
    answers: [
      { text: 'tylko r', correct: false },
      { text: 'rx', correct: true },
      { text: 'rwx', correct: false },
      { text: 'żadne', correct: false },
    ],
  },
  {
    text: '383. Co użytkownik może zrobić za pomocą komendy ulimit?',
    answers: [
      { text: 'zwiększyć swoje uprawnienia dostępu do plików', correct: false },
      {
        text: 'zablokować możliwość dokonywania zrzutu obrazu pamięci procesu do pliku (core dump)',
        correct: true,
      },
      {
        text: 'ograniczyć liczbę jednocześnie otwartych plików',
        correct: true,
      },
      {
        text: 'ograniczyć uprawnienia dostępu do swoich plików dla innych użytkowników',
        correct: false,
      },
    ],
  },
  {
    text: '384. Jakie mechanizmy kryptograficzne są niezbędne w celu zapewnienia niezaprzeczalności (ang. nonrepudiation) w kontekście poczty elektronicznej?',
    answers: [
      {
        text: 'wiadomość musi być podpisana elektronicznie kluczem publicznym nadawcy',
        correct: false,
      },
      {
        text: 'wiadomość musi być podpisana elektronicznie kluczem prywatnym nadawcy',
        correct: true,
      },
      {
        text: 'do wiadomości musi zostać dołączony certyfikat poświadczony przez zaufany urząd CA',
        correct: true,
      },
      {
        text: 'wiadomość musi zostać zaszyfrowana kluczem symetrycznym znanym jedynie stronom komunikacji',
        correct: false,
      },
    ],
  },
  {
    text: '385. Mechanizm wirtualizacji dostępu do newralgicznych komponentów systemu Windows:',
    answers: [
      {
        text: 'dotyczy niektórych obiektów rejestru systemowego',
        correct: true,
      },
      {
        text: 'może być włączany/wyłączany przez użytkownika dla jego własnych procesów',
        correct: false,
      },
      { text: 'dotyczy niektórych obiektów systemu plików', correct: true },
      {
        text: 'jest stosowany wyłącznie wobec aplikacji 64-bitowych',
        correct: false,
      },
    ],
  },
  {
    text: '386. Których wpisów ACE na liście POSIX ACL dotyczy maska:',
    answers: [
      { text: 'właściciela obiektu', correct: false },
      { text: 'grupy (domyślnej) pliku (z bazowych ACE)', correct: true },
      { text: 'każdej jawnie wpisanej grupy', correct: true },
      {
        text: 'wszystkich użytkowników niewpisanych jawnie, ale należących do dowolnej jawnie wpisanej grupy',
        correct: true,
      },
    ],
  },
  {
    text: '387. Wskaż wszystkie warunki konieczne do weryfikacji podpisu cyfrowego wiadomości S/MIME:',
    answers: [
      {
        text: 'uprzednie przekazanie do nadawcy klucza publicznego odbiorcy',
        correct: false,
      },
      {
        text: 'dostęp odbiorcy do certyfikatu klucza publicznego CA, który certyfikował klucz publiczny nadawcy',
        correct: true,
      },
      {
        text: 'uprzednie przekazanie do odbiorcy klucza publicznego nadawcy',
        correct: true,
      },
      {
        text: 'poprawna wymiana kluczy między nadawcą a odbiorcą metodą Diffiego-Hellmana',
        correct: false,
      },
    ],
  },
  {
    text: '388. $ getfacl skrypt user::rw- user:jbond:r-x group::rwx group:agents:rwx mask::r-x other::- Oznacza, że:',
    answers: [
      { text: 'grupa agents może zmodyfikować skrypt', correct: false },
      {
        text: 'grupa domyślna (owning group) może zmodyfikować skrypt',
        correct: false,
      },
      { text: 'użytkownik jbond może wykonać skrypt', correct: true },
      { text: 'pozostali użytkownicy mogą zmodyfikować skrypt', correct: true },
    ],
  },
  {
    text: '389. TCP Wrapper może korzystać z dwóch plików z regułami polityki, przy czym:',
    answers: [
      {
        text: 'ponieważ stosuje zasadę pierwszego dopasowania, plik /etc/hosts.deny może nie być w ogóle sprawdzany',
        correct: true,
      },
      {
        text: 'jeśli reguła nie zostaje odnaleziona w żadnym pliku, to dostęp zostaje odrzucony',
        correct: false,
      },
      {
        text: 'najpierw sprawdzane są reguły z pliku /etc/hosts.deny, a ewentualnie później reguły z pliku /etc/hosts.allow',
        correct: false,
      },
      {
        text: 'najpierw sprawdzane są reguły z pliku /etc/hosts.allow, a ewentualnie później reguły z pliku /etc/hosts.deny',
        correct: true,
      },
    ],
  },
  {
    text: '390. Które stwierdzenia najlepiej opisują mechanizm Bypass Traverse Checking:',
    answers: [
      {
        text: 'pozwala na wyświetlanie zawartości katalogu, do którego użytkownik nie ma przyznanego dostępu, ale ma dostęp do któregokolwiek pliku wewnątrz',
        correct: false,
      },
      {
        text: 'pozwala na ominięcie sprawdzania uprawnień do katalogów na ścieżce do pliku, do którego użytkownik ma przyznany dostęp',
        correct: true,
      },
      {
        text: 'pozwala na zestawianie tunelu IPsec w sieci wykorzystującej NAT (NAT-T)',
        correct: false,
      },
      {
        text: 'pozwala na dostęp do udziałów sieciowych bez konieczności posiadania konta w zdalnym systemie',
        correct: false,
      },
    ],
  },
  {
    text: '391. Które z poniższych poleceń pozwolą ustawić bit SGID dla katalogu dir:',
    answers: [
      { text: 'set-suid dir', correct: false },
      { text: 'chmod g+s dir', correct: true },
      { text: 'sgid -- set dir', correct: false },
      { text: 'setfacl -m group :: s', correct: false },
    ],
  },
  {
    text: '392. PGP (GPG) używane jest do:',
    answers: [
      { text: 'realizacji tuneli VPN', correct: false },
      {
        text: 'podpisywania plików muzycznych celem zachowania praw autorskich DRM',
        correct: false,
      },
      { text: 'podpisywania danych', correct: true },
      { text: 'szyfrowania plików', correct: true },
    ],
  },
  {
    text: '393. $getfacl test owner: jbond group: agents user::rw- user:jbond:r-x group:agents:--x mask::r-x other:--- W takim wypadku użytkownik jbond (będący właścicielem obiektu test), należący do grupy agents, ma efektywne uprawnienia:',
    answers: [
      { text: 'rw', correct: true },
      { text: 'rx', correct: false },
      { text: 'r', correct: false },
      { text: 'rwx', correct: false },
    ],
  },
  {
    text: '394. Wybierz prawdziwe stwierdzenie dotyczące poniższego polecenia: ssh -L 9999:neptun:23 pluton',
    answers: [
      {
        text: 'dane kierowane na port 9999 systemu neptun zostaną przesłane w niezabezpieczonej formie na port 23 systemu pluton',
        correct: false,
      },
      {
        text: 'dane kierowane na port 9999 lokalnego systemu zostaną przesłane w niezabezpieczonej formie na port 23 systemu neptun',
        correct: false,
      },
      {
        text: 'dane kierowane na port 9999 lokalnego systemu zostaną przesłane w zaszyfrowanej formie na port 22 systemu pluton',
        correct: true,
      },
      {
        text: 'w wyniku polecenia zestawiony zostanie tunel kryptograficzny między systemem neptun i systemem pluton',
        correct: false,
      },
    ],
  },
  {
    text: '395. Windows Firewall pozwala tworzyć reguły:',
    answers: [
      { text: 'przepuszczające wybrany ruch', correct: true },
      {
        text: 'blokujące wysyłanie ruchu sieciowego przez wskazane programy',
        correct: true,
      },
      {
        text: 'blokujące odbieranie ruchu sieciowego przez wskazane programy',
        correct: true,
      },
      { text: 'blokujące wybrany ruch', correct: true },
    ],
  },
  {
    text: '396. Poleceniem ulimit użytym przez użytkownika w powłoce można:',
    answers: [
      {
        text: 'stworzyć ograniczenie zasobów obowiązujące wszystkie procesy tego użytkownika w systemie (także już te istniejące)',
        correct: false,
      },
      {
        text: 'stworzyć ograniczenie zasobów obowiązujące wszystkie nowe procesy tego użytkownika w systemie',
        correct: false,
      },
      {
        text: 'stworzyć ograniczenie zasobów obowiązujące wszystkie procesy tego użytkownika w systemie, ale tylko aż do zakończenia bieżącej sesji (wylogowanie użytkownika)',
        correct: false,
      },
      {
        text: 'stworzyć ograniczenia zasobów obowiązujące tylko daną powłokę i jej procesy potomne',
        correct: true,
      },
    ],
  },
  {
    text: '397. Klucz z certyfikatu EFS użytkownika U jest wykorzystywany w systemie NTFS do:',
    answers: [
      {
        text: 'szyfrowania jednorazowych kluczy, którymi zaszyfrowane zostały poszczególne pliki do których U ma dostęp',
        correct: true,
      },
      {
        text: 'szyfrowania i deszyfrowania treści plików należących do U',
        correct: false,
      },
      {
        text: 'szyfrowania i deszyfrowania wszelkiej komunikacji z użytkownikiem U (np. poczty elektronicznej)',
        correct: false,
      },
      {
        text: 'szyfrowania i deszyfrowania treści plików należących do użytkowników, którzy udostępnili te pliki użytkownikowi U',
        correct: false,
      },
    ],
  },
  {
    text: '398. Użytkownik U systemu Linux jest właścicielem zasobu O w systemie plików i na liście ACL tego zasobu ma przyznane prawa rw, a maska zawiera prawa r oraz x. Jakie efektywne uprawnienia do O posiada aktualnie U?',
    answers: [
      { text: 'tylko r', correct: false },
      { text: 'tylko w', correct: false },
      { text: 'rw', correct: true },
      { text: 'rwx', correct: false },
    ],
  },
  {
    text: '399. Mechanizm mandatory Integrity Control (MIC) system Windows:',
    answers: [
      {
        text: 'pozwala ograniczyć swobodę komunikacji między procesami',
        correct: true,
      },
      {
        text: 'pozwala ograniczyć dostęp do zapisu w systemie plików',
        correct: true,
      },
      {
        text: 'pozwala ograniczyć dostęp do odczytu dla wybranych plików',
        correct: false,
      },
      {
        text: 'przypisuje procesowi jeden z kilku poziomów uprawnień uwzględnianych dodatkowo w kontroli dostępu',
        correct: true,
      },
    ],
  },
  {
    text: '400. Dany jest plik Tajne.txt w katalogu Jawne. Załóżmy, że użytkownik Adaś należy do grupy Users. Katalog Jawne ma przydzielone uprawnienia ACL dla grupy Users: ALLOW na czytanie i DENY na zapis. Plik Tajne.txt ma uprawnienia ALLOW na zapis dla użytkownika Adaś. Jakie uprawnienia ostatecznie ma Adaś do pliku Tajne.txt?',
    answers: [
      {
        text: 'ma uprawnienia do odczytu, brak uprawnień do zapisu',
        correct: false,
      },
      { text: 'brak uprawnień do odczytu i zapisu', correct: false },
      { text: 'ma uprawnienia do odczytu i zapisu', correct: false },
      {
        text: 'ma uprawnienia do zapisu, brak uprawnienia do odczytu',
        correct: true,
      },
    ],
  },
  {
    text: '401. Mechanizm sudo umożliwia:',
    answers: [
      {
        text: 'miękkie (soft) zmniejszenie limitów użytkownika',
        correct: false,
      },
      {
        text: 'uruchamianie poleceń z uprawnieniami administratora po podaniu własnego (domyślnie) hasła',
        correct: true,
      },
      {
        text: 'miękkie (soft) zwiększenie limitów użytkownika',
        correct: false,
      },
      {
        text: 'uruchamianie wybranych aplikacji z uprawnieniami innych użytkowników',
        correct: true,
      },
    ],
  },
  {
    text: '402. Czym różnią się klauzule DROP i REJECT w akcjach reguły iptables?',
    answers: [
      {
        text: 'obie odrzucają pakiety, ale REJECT dotyczy tylko łańcucha FORWARD',
        correct: false,
      },
      {
        text: 'obie odrzucają pakiety, ale DROP zawsze robi to "po cichu"',
        correct: true,
      },
      {
        text: 'obie odrzucają pakiety, ale DROP powoduje przerwanie przeglądania reguł, a REJECT nie',
        correct: false,
      },
      {
        text: 'REJECT odrzuca pakiety warunkowo, a DROP bezwarunkowo',
        correct: false,
      },
    ],
  },
  {
    text: '403. Autentyczność kluczy publicznych PGP jest weryfikowana:',
    answers: [
      {
        text: 'poprzez PKI (infrastrukturę klucza publicznego)',
        correct: false,
      },
      {
        text: 'przez pozyskanie certyfikatu klucza publicznego',
        correct: false,
      },
      {
        text: 'metodą Web of Trust, w której użytkownicy PGP podpisują sobie wzajemnie klucze',
        correct: true,
      },
      {
        text: 'poprzez weryfikację podpisu urzędu CA pod kluczem użytkownika',
        correct: false,
      },
    ],
  },
  {
    text: '404. Które zdania są prawdziwe w odniesieniu do aktywnego mechanizmu UAC w systemie Windows:',
    answers: [
      {
        text: 'jeśli zwykły użytkownik chce wykonać operację wymagającą uprawnień administratora zostanie zapytany o hasło administratora',
        correct: true,
      },
      {
        text: 'UAC blokuje możliwość instalacji programów przez administratora',
        correct: false,
      },
      {
        text: 'zmiana istotnych gałęzi rejestru systemu wymaga świadomej reakcji uprawnionego użytkownika',
        correct: true,
      },
      {
        text: 'UAC chroni przed przypadkowym uruchomieniem potencjalnie niebezpiecznych programów przez użytkownika',
        correct: true,
      },
    ],
  },
  {
    text: '405. Które stwierdzenia dotyczące blokady konta w systemie Windows są prawdziwe:',
    answers: [
      {
        text: 'licznik prób logowania jest zerowany po każdej udanej próbie logowania',
        correct: true,
      },
      {
        text: 'w czasie określonym długością okresu zerowania licznika prób logowania, użytkownik nie może podjąć więcej udanych prób logowania niż określa próg blokady',
        correct: false,
      },
      {
        text: 'istnieje ustawienie progu blokady dopuszczające nieblokowanie konta mimo dowolnej liczby niepomyślnych prób logowania',
        correct: true,
      },
      {
        text: 'próg blokady określa ilość kolejnych niepomyślnych prób logowania, po osiągnięciu której dostęp do konta będzie zablokowany trwale (do odwołania przez administratora)',
        correct: false,
      },
    ],
  },
  {
    text: '406. Czy pakiet PGP(GPG) używa szyfrowania symetrycznego?',
    answers: [
      {
        text: 'tak, treść listu jest zawsze szyfrowana algorytmem symetrycznym',
        correct: true,
      },
      {
        text: 'nie, PGP stosuje tylko kryptografię klucza publicznego',
        correct: false,
      },
      { text: 'tak, np. do szyfrowania plików', correct: true },
      {
        text: 'tak, nadawca i odbiorca generują metodą DH wspólny klucz sesji na podstawie swoich kluczy publicznych',
        correct: false,
      },
    ],
  },
  {
    text: '407. Bezpośrednim efektem operacji eksportu certyfikatu do formatu PKCS#12 jest:',
    answers: [
      {
        text: 'przekazanie klucza publicznego innemu użytkownikowi w celu umożliwienia mu wysłania do nas zaszyfrowanej poczty',
        correct: false,
      },
      {
        text: 'wyodrębnienie z certyfikatu klucza publicznego w celu dołączenia go do kryptogramu przesyłanej wiadomości',
        correct: false,
      },
      {
        text: 'wyodrębnienie z certyfikatu klucza prywatnego w celu dołączenia go do wykonanego podpisu elektronicznego wiadomości',
        correct: false,
      },
      {
        text: 'utworzenie kopii zapasowej klucza prywatnego i publicznego w pliku',
        correct: true,
      },
    ],
  },
  {
    text: '408. Mechanizm sudo można tak skonfigurować by:',
    answers: [
      { text: 'nigdy nie wymagał podania hasła', correct: true },
      {
        text: 'wymagał podania hasła użytkownika, w ramach konta którego należy wykonać polecenie',
        correct: false,
      },
      {
        text: 'wykonał polecenie bez pytania o hasło użytkownika o ile plik programu tego polecenia ma ustawiony bit SUID',
        correct: false,
      },
      {
        text: 'wymagał podania hasła bieżącego użytkownika przy każdym poleceniu',
        correct: true,
      },
    ],
  },
  {
    text: '409. Możliwe metody uwierzytelniania użytkownika w protokole SSH:',
    answers: [
      { text: 'hasło użytkownika', correct: true },
      { text: 'mechanizm TOFU (Trust On First Use)', correct: false },
      { text: 'asymetryczne klucze kryptograficzne', correct: true },
      { text: 'symetryczne klucze kryptograficzne', correct: false },
    ],
  },
  {
    text: '410. Wskaż prawdziwe stwierdzenia dotyczące szyfrowania treści plików mechanizmem EFS:',
    answers: [
      {
        text: 'każdy plik szyfrowany jest kluczem publicznym właściciela pliku',
        correct: false,
      },
      { text: 'każdy plik szyfrowany jest innym kluczem', correct: true },
      {
        text: 'plik udostępniony przez właściciela 2 innym użytkownikom jest szyfrowany 3 kluczami',
        correct: true,
      },
      {
        text: 'każdy plik szyfrowany jest kluczem prywatnym właściciela pliku',
        correct: false,
      },
    ],
  },
  {
    text: '411. Protokół TLS w usłudze poczty elektronicznej stosuje się do:',
    answers: [
      {
        text: 'tworzenia bezpiecznego kanału komunikacji programu klienta z serwerem poczty',
        correct: true,
      },
      {
        text: 'uwierzytelniania nadawcy konkretnej wiadomości',
        correct: false,
      },
      { text: 'podpisywania cyfrowego treści listy', correct: false },
      { text: 'szyfrowania załączników wiadomości', correct: false },
    ],
  },
  {
    text: '412. Który opis pasuje do poniższej konfiguracji TCP wrappera: ftpd: ALL EXCEPT www : ALLOW ALL : ALL : twist /bin/echo "OK"',
    answers: [
      {
        text: 'za wyjątkiem komputera www umożliwia każdemu dostęp do każdej usługi',
        correct: false,
      },
      {
        text: 'zabrania dostępu do usługi WWW z komputera ftpd',
        correct: false,
      },
      {
        text: 'umożliwia dostęp do usługi FTP z komputera www',
        correct: false,
      },
      { text: 'zabrania dostępu do usługi FTP z komputera www', correct: true },
    ],
  },
  {
    text: '413. Pliki zwirtualizowane mechanizmem UAC przechowywane są w systemie Windows w:',
    answers: [
      {
        text: 'katalogu "%WINDIR%\\User Access Container\\Sandbox"',
        correct: false,
      },
      { text: 'katalogu "%SYSTEMDRIVE%\\VirtualStore"', correct: false },
      {
        text: 'katalogu "VirtualStore" lokalnym dla każdego użytkownika',
        correct: true,
      },
      {
        text: 'alternatywnych strumieniach danych (ADS) systemu NTFS',
        correct: false,
      },
    ],
  },
  {
    text: '414. Czego nie można ograniczyć za pomocą komendy ulimit (mechanizmu limitów zasobowych)?',
    answers: [
      { text: 'wielkości pliku zrzutu pamięci', correct: false },
      { text: 'ilości otwartych deskryptorów', correct: false },
      { text: 'ilości tworzonych procesów', correct: false },
      {
        text: 'sumy zajmowanej przestrzeni dyskowej przez pliki',
        correct: true,
      },
    ],
  },
  {
    text: '415. Polecenie netsh advfirewall firewall add rule name="private" protocol=icmpv4 action=block dir=out remoteip=10.10.0.2 blokuje:',
    answers: [
      {
        text: 'pingowania adresu 10.10.0.2 niezależnie od użycia IPv4 czy IPv6',
        correct: false,
      },
      {
        text: 'pingowania adresu 10.10.0.2 tylko w sieci o profily prywatnym',
        correct: false,
      },
      {
        text: 'pingowania tylko po IPv4 bieżącego systemu z adresu 10.10.0.2 (bez wpływu na IPv6)',
        correct: false,
      },
      {
        text: 'pingowania tylko po IPv4 adresu z bieżącego system 10.10.0.2 (bez wpływu na IPv6)',
        correct: true,
      },
    ],
  },
  {
    text: '416. W jak można udostępnić swój klucz publiczny PGP innemu użytkownikowi:',
    answers: [
      { text: 'przekazać osobiście na nośniku wymiennym', correct: true },
      { text: 'umieścić na swojej stronie www', correct: true },
      { text: 'wysłać pocztą elektroniczną', correct: true },
      {
        text: 'umieścić w sieciowym repozytorium kluczy (tzw. serwerze kluczy)',
        correct: true,
      },
    ],
  },
  {
    text: '417. Ataki o nazwie phishing:',
    answers: [
      { text: 'dotyczą wykradzenia zaufanych certyfikatów CA', correct: false },
      { text: 'realizowane są za pośrednictwem poczty', correct: true },
      { text: 'polegają na zatruwania cache przeglądarki www', correct: false },
      { text: 'realizowane są za pośrednictwem www', correct: true },
    ],
  },
  {
    text: '418. Które z wymienionych poniżej mechanizmów wspomagają wykrywanie podsłuchu w sieci:',
    answers: [
      { text: '802.1X', correct: false },
      { text: 'ARP', correct: true },
      { text: '802.11X', correct: false },
      { text: 'ICMP echo', correct: false },
    ],
  },
  {
    text: '419. Metoda Diffiego-Hellmana:',
    answers: [
      {
        text: 'pozwala stronom komunikacji bezpiecznie ustalić wspólne klucze asymetryczne',
        correct: false,
      },
      {
        text: 'wymaga szyfrowania negocjacji w celu ochrony przed atakami pasywnymi',
        correct: false,
      },
      {
        text: 'pozwala stronom komunikacji bezpiecznie ustalić wspólny klucz symetryczny',
        correct: true,
      },
      {
        text: 'wymaga uwierzytelniania negocjacji w celu ochrony przed atakami aktywnym',
        correct: true,
      },
    ],
  },
  {
    text: '420. Które z poniższych protokołów służą do realizacji kryptograficznych tuneli wirtualnych:',
    answers: [
      { text: 'TLS', correct: true },
      { text: 'SSO', correct: false },
      { text: 'IKE', correct: true },
      { text: 'ESP', correct: true },
    ],
  },
  {
    text: '421. Wskaż cechy charakteryzujące kontrole dostępu MAC:',
    answers: [
      {
        text: 'tylko właściciel zasobu może dysponować prawami dostępu do tego zasobu',
        correct: false,
      },
      {
        text: 'etykiety ochrony danych przypisane do zasobów automatycznie wymuszają uprawnienia',
        correct: true,
      },
      {
        text: 'właściciel zasobu nie może dysponować prawami dostępu do tego zasobu',
        correct: true,
      },
      {
        text: 'tylko wyróżniony oficer bezpieczeństwa może dysponować prawami dostępu do zasobów',
        correct: true,
      },
    ],
  },
  {
    text: '422. Wskaż możliwe sposoby ochrony przed atakami na protokół DHCP (takimi jak np. DHCP redirection, lease starvation):',
    answers: [
      {
        text: 'DHCP Snooping - przełącznik przepuszcza odpowiedzi DHCP tylko z określonego wcześniej portu',
        correct: true,
      },
      {
        text: 'DHCP Hoping - zapora zamienia numer VLAN w zadaniach DHCP',
        correct: false,
      },
      {
        text: 'ICMP redirection - wykorzystanie ICMP do ponownej zmiany trasy pakietów DHCP',
        correct: false,
      },
      {
        text: 'DHCP session hijacking - przejmowanie połączeń TCP sesji DHCP przez proxy',
        correct: false,
      },
    ],
  },
  {
    text: '423. W model uwierzytelniania z udziałem zaufanej trzeciej strony, do zadań tej trzeciej strony należy:',
    answers: [
      {
        text: 'pobieranie danych uwierzytelniających od strony uwierzytelnionej',
        correct: false,
      },
      {
        text: 'wystawienie poświadczenia uwierzytelnienia stronie uwierzytelnionej',
        correct: true,
      },
      {
        text: 'przekazane danych uwierzytelniających strony uwierzytelnionej docelowym serwerowi',
        correct: false,
      },
      {
        text: 'przekazane danych uwierzytelniających stronie uwierzytelnionej',
        correct: false,
      },
    ],
  },
  {
    text: '424. Wskaż protokoły wymagające zabezpieczenia autentyczności i integralności danych, ale niekoniecznie poufności:',
    answers: [
      { text: 'DNS (Domain Name Service', correct: true },
      { text: 'ARP (Address Resolution Protocol)', correct: true },
      { text: 'STP (Spanning Tree Protocol)', correct: true },
      { text: 'rlogin (Remote Login)', correct: false },
    ],
  },
];
