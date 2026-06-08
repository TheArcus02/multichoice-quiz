export const aiQuestions = [
  {
    text: "Zjawisko nadmiernego dopasowania (ang. overfiting) drzewa do danych uczących można unikać poprzez:",
    answers: [
      { text: "transformacje drzewa na zbiór reguł", correct: false },
      {
        text: "użycie zmodyfikowanej miary informacyjnej zamiast entropii",
        correct: false,
      },
      { text: "pruning - redukcję rozmiarów drzewa", correct: true },
      {
        text: "poszukiwanie przykładów pełniących rolę outlier",
        correct: false,
      },
    ],
  },
  {
    text: "Które zdanie o sieciach neuronowych jest fałszywe?",
    answers: [
      { text: "Sieć może zawierać elementy nieliniowe", correct: false },
      { text: "Sieć uczy się poprzez zmiany wag i biasów", correct: false },
      {
        text: "Sieć może mieć formę arbitralnego grafu pojedynczych neuronów zamiast warstw",
        correct: false,
      },
      { text: "Sieć musi być uczona gradientowo", correct: true },
    ],
  },
  {
    text: "Które zdanie o sieciach neuronowych jest prawdziwe?",
    answers: [
      {
        text: "Sieć neuronowa zaczyna od losowej klasyfikacji przypadków, i z czasem poprawia rezultaty w wyniku procesu uczenia.",
        correct: true,
      },
      {
        text: "Sieci neuronowe to paradygmat uczenia maszynowego, który łatwo podlega interpretacji jeżeli chodzi o powody klasyfikacji przypadków.",
        correct: false,
      },
      {
        text: "Sieć neuronowa przyjmuje na wejście kilka przypadków ze zbioru uczącego, które agreguje.",
        correct: false,
      },
      {
        text: "Sieć neuronowa dokonuje klasyfikacji przypadków stochastycznie, tzn. wynik klasyfikacji może się różnić przy wielu uruchomieniach danej sieci neuronowej.",
        correct: false,
      },
    ],
  },
  {
    text: "Co jest zadaniem autoenkodera w zadaniu autoasocjacji?",
    answers: [
      { text: "Minimalizacja wariancji na wyjściu.", correct: false },
      { text: "Odtworzenie na wyjściu oryginalnego wejścia.", correct: true },
      { text: "Klasyfikacja do właściwej klasy decyzyjnej.", correct: false },
      {
        text: "Wskazanie najważniejszych grup (klastrów) w danych.",
        correct: false,
      },
    ],
  },
  {
    text: "Ile sumarycznie węzłów wewnętrznych i liści będzie miało drzewo wyindukowane dla zbioru uczącego, którego wszystkie przykłady należą do jednej klasy?",
    answers: [
      { text: "0", correct: false },
      { text: "2", correct: false },
      { text: "1", correct: true },
      { text: "co najmniej 3", correct: false },
    ],
  },
  {
    text: "Zbiór danych liczy 1000 przypadków. Chcemy wykorzystać te dane do nadzorowanego uczenia. Które z zaproponowanych podejść jest poprawne?",
    answers: [
      {
        text: "Podzielić dane na k grup (tzw. foldów), i k razy, w ramach każdego indywidualnego folda, uruchomić uczenie i testowanie.",
        correct: false,
      },
      {
        text: "Podzielić dane na podzbiory w proporcji odpowiednio 1:2 i uczyć się na pierwszym podzbiorze, a testować na wszystkich danych.",
        correct: false,
      },
      {
        text: "Przeznaczyć ustalony procent danych do testowania, i uczyć się wyłącznie na reszcie.",
        correct: true,
      },
      {
        text: "Nauczyć się na wszystkich danych, a następnie testować na losowo wybranych przypadkach.",
        correct: false,
      },
    ],
  },
  {
    text: "Technika wczesnego kończenia uczenia sieci (early stopping) przy wykorzystaniu zbioru walidacyjnego polega na:",
    answers: [
      {
        text: "Przerwaniu uczenia sieci kiedy błąd na zbiorze walidacyjnym zacznie wzrastać.",
        correct: true,
      },
      {
        text: "Zoptymalizowaniu działania sieci na zbiorze walidacyjnym, a potem dopiero douczeniu jej na zbiorze uczącym.",
        correct: false,
      },
      {
        text: "Usunięciu ze zbioru walidacyjnego wszystkich outlierów.",
        correct: false,
      },
      {
        text: "Dodaniu specjalnej warstwy walidacyjnej do sieci neuronowej.",
        correct: false,
      },
    ],
  },
  {
    text: 'Pojęcie "przekleństwo wymiarowości" mówi o:',
    answers: [
      {
        text: "wzroście złożoności obliczeniowej wraz ze wzrostem liczby atrybutów",
        correct: false,
      },
      {
        text: "spadku jakości klasyfikacji za każdym razem po dodaniu kolejnego atrybutu",
        correct: false,
      },
      {
        text: "konieczności wykładniczego wzrostu liczby przykładów uczących przy rosnącej liczbie atrybutów (aby utrzymać jakość klasyfikacji)",
        correct: true,
      },
      {
        text: "żadna z pozostałych odpowiedzi nie jest poprawna",
        correct: false,
      },
    ],
  },
  {
    text: "Początkowe centroidy w algorytmie k-means:",
    answers: [
      {
        text: "zawsze ustalane są na wartości kolejne wartości co 1/k przedziału wartości na wszystkich atrybutach",
        correct: false,
      },
      {
        text: "w pierwszej iteracji jest tylko jeden centroid w połowie przedziału każdego atrybutu",
        correct: false,
      },
      {
        text: "mogą być ustalone jako losowe przykłady z danych",
        correct: true,
      },
      {
        text: "ich wybór nie ma wpływu na końcowe przydziały do grup",
        correct: false,
      },
    ],
  },
  {
    text: "Jakie są główne wady algorytmu k-means w porównaniu do innych algorytmów grupowania?",
    answers: [
      {
        text: "wolne działanie, brak odporności na zaszumienie przypadków",
        correct: false,
      },
      {
        text: "tworzenie kulistych skupień, skupienia trudne w interpretacji",
        correct: false,
      },
      {
        text: "tworzenie kulistych skupień, brak odporności na przypadki odstające",
        correct: true,
      },
      {
        text: "skupienia trudne w interpretacji, brak odporności na przypadki odstające",
        correct: false,
      },
    ],
  },
  {
    text: "Co można odczytać z macierzy pomyłek?",
    answers: [
      {
        text: "Liczbę skupień na jakie podzielone zostały dane i liczby przypadków do nich należących",
        correct: false,
      },
      {
        text: "Trafność klasyfikacji i złożoność klasyfikatora",
        correct: false,
      },
      {
        text: "Liczności klas decyzyjnych i złożoność klasyfikatora",
        correct: false,
      },
      {
        text: "Trafność klasyfikacji i liczności klas decyzyjnych",
        correct: true,
      },
      {
        text: "Przypadki odstające w danych i błąd średniokwadratowy",
        correct: false,
      },
    ],
  },
  {
    text: "Uczenie nadzorowane łączy z nienadzorowanym to, że:",
    answers: [
      {
        text: "zazwyczaj nie mają hiperparametrów określających ich działanie",
        correct: false,
      },
      { text: "mogą zostać użyte te same algorytmy uczenia", correct: false },
      {
        text: "oba mogą wykorzystać selekcję atrybutów bazującą na korelacji z atrybutem decyzyjnym",
        correct: false,
      },
      {
        text: "często bardzo podobne przypadki dostaną podobną odpowiedź (klasyfikację lub przydział do skupienia)",
        correct: true,
      },
    ],
  },
  {
    text: "Zadaniem warstwy poolingu jest:",
    answers: [
      {
        text: "Agregacja wartości z pewnego fragmentu tensora do jednej wartości",
        correct: true,
      },
      { text: "Regularyzacja sieci", correct: false },
      { text: "Zwiększenie wymiarowości danych", correct: false },
      {
        text: "Agregacja kilku przypadków uczących do jednego tensora",
        correct: false,
      },
      { text: "Normalizowanie danych", correct: false },
    ],
  },
  {
    text: "Przy k = 1 algorytm k-NN:",
    answers: [
      {
        text: "jest odporny na przykłady odstające (outliers)",
        correct: false,
      },
      { text: "zawsze daje gorsze rezultaty niż przy k = 3", correct: false },
      {
        text: "daje dobre wyniki (jakość klasyfikacji) jeżeli w zbiorze danych klasy są wyraźnie rozdzielone",
        correct: true,
      },
    ],
  },
  {
    text: "Eksperymentalnego doboru wartości k w algorytmie k-NN NIE można wykonać wykorzystując:",
    answers: [
      { text: "zbiór testowy", correct: true },
      { text: "kroswalidację", correct: false },
      { text: "zbiór walidacyjny", correct: false },
    ],
  },
  {
    text: "Która z poniższych odpowiedzi dotyczących biasu używanego w neuronie jest prawdziwa?",
    answers: [
      {
        text: "Bias jest dodawany przed zaaplikowaniem funkcji aktywacji.",
        correct: true,
      },
      {
        text: "Bias jest stały podczas uczenia, wagi muszą się dostosować do dobranych wartości biasu.",
        correct: false,
      },
      {
        text: "Neuron podczas agregacji dodaje uśrednioną wartość biasu połączonych z nim neuronów z poprzedniej warstwy.",
        correct: false,
      },
      {
        text: "Z biasu można zrezygnować bez szkody dla jakości klasyfikacji sieci.",
        correct: false,
      },
    ],
  },
  {
    text: "Przeuczenie polega na tym, że:",
    answers: [
      {
        text: "klasyfikator osiągnął minimalny możliwy błąd na danych testowych",
        correct: false,
      },
      {
        text: "błąd klasyfikatora na zbiorze uczącym jest niższy niż testowym",
        correct: true,
      },
      { text: "klasyfikator działa zbyt dobrze", correct: false },
      {
        text: "klasyfikator przestał działać na skutek zbyt długiego uczenia",
        correct: false,
      },
    ],
  },
  {
    text: "Uczenie nadzorowane różni się od nienadzorowanego tym, że:",
    answers: [
      {
        text: "w uczeniu nadzorowanym mamy zdefiniowane atrybuty",
        correct: false,
      },
      {
        text: "w uczeniu nadzorowanym mamy odgórnie narzuconą miarę odległości między przypadkami",
        correct: false,
      },
      {
        text: "w uczeniu nadzorowanym mamy wskazany atrybut którego wartości mamy przewidywać",
        correct: true,
      },
      {
        text: "w uczeniu nadzorowanym ekspert na bieżąco ocenia jakość każdej indywidualnej predykcji",
        correct: false,
      },
    ],
  },
  {
    text: "Która z poniższych metod selekcji atrybutów nie wykorzystuje do działania żadnej dodatkowej miary oceny jakości atrybutu:",
    answers: [
      { text: "sort", correct: false },
      { text: "filter", correct: false },
      { text: "wrapper", correct: true },
      { text: "entropy", correct: false },
    ],
  },
  {
    text: "W jaki sposób należy obliczyć zmienną δA w algorytmie wstecznej propagacji błędu dla pojedynczego neuronu? Załóżmy, że X ∈ {P, Q, R}.",
    answers: [
      {
        text: "Należy znaleźć maksymalną wartość błędu δX, a następnie pomnożyć ją przez pochodną funkcji aktywacji neuronu A, f′(zA)",
        correct: false,
      },
      {
        text: "Należy obliczyć sumę ważoną wszystkich δX wchodzących po wagach wA,X, a następnie pomnożyć ją przez pochodną funkcji aktywacji neuronu A, f′(zA)",
        correct: true,
      },
      {
        text: "Należy zsumować wszystkie δX, a następnie pomnożyć przez pochodną funkcji aktywacji neuronu A, f′(zA)",
        correct: false,
      },
      {
        text: "Należy uśrednić wszystkie δX, a następnie pomnożyć przez pochodną funkcji aktywacji neuronu A, f′(zA)",
        correct: false,
      },
    ],
  },
  {
    text: "Jeżeli wykryty zostanie relatywnie duży poziom szumu w zbiorze uczącym, która z akcji podanych poniżej będzie właściwą aby jakość klasyfikacji była jak najwyższa:",
    answers: [
      {
        text: "brak działania (zmiana wartości k nie wpłynie na jakość klasyfikacji w zaszumionych danych)",
        correct: false,
      },
      { text: "zwiększenie wartości k", correct: true },
      { text: "zmniejszenie wartości k", correct: false },
    ],
  },
  {
    text: "W pewnej iteracji algorytmu k-means (k=2) podzielono zbiór danych na następujące podzbiory: K1: (1,3), (2,7) oraz K2: (6,2), (0,10). Jakie będą wartości atrybutów dla centroidów w kolejnej iteracji?",
    answers: [
      { text: "Centroid K1: (1.5, 5), centroid K2: (3, 6)", correct: true },
      { text: "Centroid K1: (2,6), centroid K2: (1,5)", correct: false },
      { text: "Centroid K1: (3, 7), centroid K2: (6, 10)", correct: false },
      { text: "Centroid K1: (1, 2), centroid K2: (2, 0)", correct: false },
    ],
  },
  {
    text: "Który z poniższych sposobów NIE jest dobrym sposobem na poradzenie sobie z brakującą wartością atrybutu dla przypadku uczącego?",
    answers: [
      {
        text: "Wstawienie wartości atrybutu najczęściej występującej dla klasy decyzyjnej tego przypadku",
        correct: false,
      },
      {
        text: "Skopiowanie wartości atrybutu z następnego w kolejności przypadku uczącego",
        correct: true,
      },
      { text: "Wykorzystanie dodatkowej wartości 'unknown'", correct: false },
      {
        text: "Wstawienie wartości najczęściej występującej na tym atrybucie",
        correct: false,
      },
    ],
  },
  {
    text: "Mamy sieć konwolucyjną C = Conv2D(5, (3, 3), (1,1)), która ma 5 filtrów, rozmiar kernela (3,3), przesunięcie kernela (strides) (1,1) i brak paddingu. Aplikujemy ją do obrazka w odcieniach szarości o wymiarach 100x100. Jaki będzie wymiar tensora danych po przetworzeniu przez C?",
    answers: [
      { text: "98 x 98 x 5", correct: true },
      { text: "100 x 100 x 5", correct: false },
      { text: "500 x 500", correct: false },
      { text: "100 x 100", correct: false },
      { text: "98 x 98", correct: false },
    ],
  },
  {
    text: "Algorytm k-means:",
    answers: [
      {
        text: "ustala ostateczną liczbę grup w toku działania opierając się na ustalonej wartości progu podobieństwa",
        correct: false,
      },
      { text: "jest algorytmem klasyfikacji", correct: false },
      { text: "jest algorytmem uczenia nadzorowanego", correct: false },
      { text: "wymaga znanej z góry liczby klastrów (grup)", correct: true },
    ],
  },
  {
    text: "Który z poniższych wzorów pozwoli znormalizować dane?",
    answers: [
      { text: "(X - avg(X)) / stddev(X)", correct: true },
      { text: "X - max(X)", correct: false },
      { text: "X / avg(X)", correct: false },
      { text: "(X + avg(X)) / (X - std(X))", correct: false },
    ],
  },
  {
    text: "Który atrybut zostanie wybrany do dokonania podziału w danym węźle?",
    answers: [
      {
        text: "Dzielący zbiór przypadków na podzbiory o możliwie jednolitych decyzjach",
        correct: true,
      },
      { text: "Mający najwyższą wartość entropii", correct: false },
      {
        text: "Losowy wg prawdopodobieństwa uzyskanego z policzenia jego entropii warunkowej ze względu na klasę decyjną",
        correct: false,
      },
      { text: "Zawierający najwięcej przypadków uczących", correct: false },
    ],
  },
  {
    text: "Ile razy klasyfikowany jest każdy przykład (jako testowy przez klasyfikator) w procedurze oceny krzyżowej (ang. k-fold cross-validation)?",
    answers: [
      {
        text: "n razy, gdzie n to liczba części na jakie jest podzielony zbiór uczący.",
        correct: false,
      },
      { text: "Dokładnie jeden raz.", correct: true },
      {
        text: "Przynajmniej raz i nie więcej niż n - 1, gdzie n to liczba części na jakie jest podzielony zbiór uczący.",
        correct: false,
      },
      {
        text: "Metoda oceny jest techniką wielu losowych podziałów, więc trudno to ustalić",
        correct: false,
      },
      {
        text: "Jest to zależne od liczby części (ang. podziałów), na jakie został losowo podzielony zbiór uczący?",
        correct: false,
      },
    ],
  },
  {
    text: "Spośród poniżej przedstawionych architektur, wskaż tę która reprezentuje typowy autoenkoder (czyli wariant undercomplete) w zadaniu autoasocjacji.",
    answers: [
      { text: "Dense(100) -> Dense(1000) -> Dense(100)", correct: false },
      { text: "Dense(100) -> Dense(10) -> Dense(100)", correct: true },
      { text: "Dense(100) -> Dense(10) -> Dense(2)", correct: false },
      { text: "Dense(100) -> Dense(100) -> Dense(100)", correct: false },
    ],
  },
  {
    text: "Który wzór reprezentuje wyjście zwrócone przez neuron z funkcją aktywacji f, wagami wi, biasem b, oraz wejściami xi?",
    answers: [
      { text: "Σ wi · f(xi + b)", correct: false },
      { text: "f(Σ wi · xi + b)", correct: true },
      { text: "Σ f(wi · xi + b)", correct: false },
      { text: "Σ wi · f(xi + b)", correct: false },
    ],
  },
  {
    text: "Przyrost informacji (ang. info gain) jest zdefiniowany jako (D - zbiór przykładów uczących, a - atrybut użyty do podziału w węźle drzewa; Ent - funkcja entropii):",
    answers: [
      { text: "Gain(D,a)=Ent(D)-Ent(D|a)", correct: true },
      { text: "Gain(D,s)=Ent(a)-Ent(s|D)", correct: false },
      { text: "Gain(D,a)=Ent(D|a)-Ent(D)", correct: false },
      { text: "Gain(D,a)=Ent(a)-Ent(D|a)", correct: false },
    ],
  },
  {
    text: "Na którym zbiorze danych powinniśmy sprawdzić, jak model zachowa się podczas wdrożenia go do pracy na potencjalnie niewidzianych wcześniej przypadkach:",
    answers: [
      { text: "nienadzorowanym", correct: false },
      { text: "uczącym", correct: false },
      { text: "testowym", correct: true },
      { text: "walidacyjnym", correct: false },
    ],
  },
  {
    text: "Mamy w sieci neuronowej pewną warstwę W1 = Dense(5). Następnie postanawiamy dodać do sieci jeszcze jedną w pełni połączoną warstwę W2 = Dense(10) po warstwie W1. Ile dodatkowych uczalnych parametrów sieci (wag i biasów) zostanie utworzonych w związku z powiększeniem architektury tej sieci?",
    answers: [
      { text: "35", correct: false },
      { text: "60", correct: true },
      { text: "15", correct: false },
      { text: "20", correct: false },
      { text: "55", correct: false },
      { text: "50", correct: false },
    ],
  },
  {
    text: "Algorytm k-NN:",
    answers: [
      {
        text: "nie tworzy modelu (predykcja odbywa się na całych danych uczących)",
        correct: true,
      },
      { text: "nie wymaga ustalenia żadnych parametrów", correct: false },
      {
        text: "może być użyty tylko z użyciem odległości euklidesowej",
        correct: false,
      },
    ],
  },
  {
    text: "Jakie będą skutki dobrania zbyt dużego współczynnika uczenia (learning rate)?",
    answers: [
      {
        text: "Proces optymalizacji zatrzyma się przedwcześnie z powodu zerowej pochodnej.",
        correct: false,
      },
      {
        text: "Nauczona sieć będzie działać niedeterministycznie.",
        correct: false,
      },
      {
        text: "Proces optymalizacji może być niezdolny dotrzeć do wartości bliskich optimum.",
        correct: true,
      },
      { text: "Sieć neuronowa przeuczy się.", correct: false },
    ],
  },
  {
    text: "Metoda Lasso jest stosowana w modelach uczenia maszynowego do:",
    answers: [
      { text: "jest rodzajem tzw. regresji grzbietowej", correct: false },
      {
        text: "jako metoda doboru parametru k podczas selekcji cech",
        correct: false,
      },
      {
        text: "do wykonania selekcji zmiennych w problemach klasyfikacyjnych",
        correct: false,
      },
      {
        text: "w przypadku regresji jako element regularyzacyjny",
        correct: true,
      },
    ],
  },
  {
    text: "Co jest prawdą dla zespołu T drzew w ramach tzw. systemu bagging?",
    answers: [
      {
        text: "Wypracowuje się decyzję końcową poprzez głosowanie większościowe",
        correct: true,
      },
      {
        text: "modyfikuje się parametry uczenia każdego drzewa dla zwiększenia ich zróżnicowania",
        correct: false,
      },
      {
        text: "stosuje się rozłączny podział przykładów w kolejnych zbiorach uczących drzew",
        correct: false,
      },
      {
        text: "Stosuje się losowanie bootstrapowe dla każdego z tych drzew",
        correct: true,
      },
    ],
  },
  {
    text: "Jakie przykłady uczące są zapamiętywane w algorytmie IBL2?",
    answers: [
      {
        text: "posiadające wysoką wartość tzw. rekordu klasyfikacyjnego",
        correct: false,
      },
      {
        text: "żadna z powyższych odpowiedzi nie jest prawdziwa",
        correct: false,
      },
      { text: "te, które są poprawnie klasyfikowane", correct: false },
      {
        text: "te, dla których podczas przyrostowego uczenia się popełniane są błędy",
        correct: true,
      },
      { text: "wszystkie", correct: false },
    ],
  },
  {
    text: "Metodą wiązania w algorytmach aglomeracyjnych może być:",
    answers: [
      { text: "wiązanie single linkage", correct: true },
      { text: "metoda Barda", correct: false },
      { text: "średnie ważone odległości Lorentza", correct: false },
      { text: "odległość najdalszego sąsiada", correct: true },
    ],
  },
  {
    text: "Autoenkoder wariacyjny różni się od zwykłego następującymi cechami:",
    answers: [
      { text: "liczbą wejść dekodera", correct: false },
      {
        text: "randomizacją sygnału przekazywanego z enkodera do dekodera",
        correct: true,
      },
      { text: "sposobem obliczania błędu rekonstrukcji", correct: false },
      { text: "funkcją straty", correct: true },
      { text: "sposobem prezentowania przykładów wejściowych", correct: false },
    ],
  },
  {
    text: "Metoda analizy dyskryminacyjnej:",
    answers: [
      {
        text: "Opiera się na minimalizacji różnicy rzutów wartości średnich w klasach oraz minimalizacji odpowiednio przekształconej macierzy kowariancji",
        correct: false,
      },
      { text: "jest odmianą algorytmu analizy skupisk", correct: false },
      {
        text: "w wersji zaproponowanej przez R. Fishera automatycznie tworzy liniową płaszczyznę separującą",
        correct: true,
      },
      {
        text: "Maksymalizuje tzw. margines decyzyjny po to aby przybliżyć granicę decyzyjną",
        correct: false,
      },
    ],
  },
  {
    text: "Które ze zdań jest prawdziwe w stosunku do algorytmu k-średnich?",
    answers: [
      {
        text: "Przy wykorzystaniu odległości euklidesowej ma ukierunkowanie do tworzenia kulistych kształtów skupisk",
        correct: true,
      },
      {
        text: "Wykorzystuje rzeczywiste obserwacje, tzw. medoidy, do reprezentacji skupienia",
        correct: false,
      },
      {
        text: "Iteracyjnie próbuje minimalizować miarę zmienności wewnątrz-skupieniowej",
        correct: true,
      },
      { text: "Sam algorytm ustala liczbę skupień", correct: false },
    ],
  },
  {
    text: "Zaletą funkcji aktywacji Leaky ReLU w porównaniu z funkcją ReLU jest:",
    answers: [
      { text: "Ciągłość pochodnej w zerze", correct: false },
      { text: "Niezerowy gradient dla ujemnych argumentów", correct: true },
      { text: "Różniczkowalność w całej dziedzinie", correct: false },
      {
        text: "Niezerowy gradient dla ujemnych argumentów i ciągłość pochodnej w zerze",
        correct: false,
      },
    ],
  },
  {
    text: "Dlaczego nie wykorzystuje się pełnej postaci klasyfikatora bayesowskiego, tylko wersję tzw. naiwnego klasyfikatora bayesowskiego?",
    answers: [
      {
        text: "nie potrafimy poprawnie oszacować prawdopodobieństwa a priori klas",
        correct: false,
      },
      {
        text: "jego obliczenie prowadzi do wyższych kosztów czasowych",
        correct: false,
      },
      { text: "grozi tzw. przeuczeniem", correct: false },
      {
        text: "gdyż oszacowanie prawdopodobieństw koniunkcji atrybutów warunkowych stwarza zbyt trudne wymagania do ich obecności w zbiorze przykładów uczących",
        correct: true,
      },
    ],
  },
  {
    text: "Wymiarowość wektora gradientu obliczanego w algorytmie spadku wzdłuż gradientu dla sieci neuronowej o n wejściach, m wyjściach i k parametrach, uczonej skalarną funkcją straty wynosi:",
    answers: [
      { text: "m", correct: false },
      { text: "m + k", correct: false },
      { text: "n + m", correct: false },
      { text: "n", correct: false },
      { text: "k", correct: true },
      { text: "n + k", correct: false },
    ],
  },
  {
    text: "Motywacją dla stosowania połączeń rezydualnych jest:",
    answers: [
      { text: "redukcja liczby parametrów modelu", correct: false },
      {
        text: "zapewnienie lepszej propagacji gradientu w procesie uczenia",
        correct: true,
      },
      {
        text: "istnienie grupy zadań dla których celem nie jest uczenie się odwzorowania y=f(x), a raczej y=f(x)+x",
        correct: false,
      },
      {
        text: "uproszczenie architektury modelu dzięki modularyzacji architektury",
        correct: false,
      },
      {
        text: "zapewnienie lepszej propagacji gradientu w procesie odpytywania modelu",
        correct: false,
      },
    ],
  },
  {
    text: "Edytowana wersja klasyfikatora k-NN:",
    answers: [
      { text: "dostraja wartość k na zbiorze walidującym", correct: false },
      {
        text: "polega na wyborze przykładów uczących do tzw. concept description",
        correct: true,
      },
      {
        text: "pozwala na selekcję atrybutów z wykorzystaniem podejścia wrapper",
        correct: false,
      },
      { text: "modyfikuje dynamicznie miarę odległości", correct: false },
    ],
  },
  {
    text: "Jak modyfikuje się zbiór przykładów uczących w algorytmie boosting?",
    answers: [
      {
        text: "modyfikuje się wagi przykładów w zależności od błędów popełnianych w poprzedniej iteracji",
        correct: true,
      },
      {
        text: "dla każdego z przykładów losuje się podzbiór atrybutów",
        correct: false,
      },
      {
        text: "nie modyfikuje się przykładów, lecz stosuje się różne algorytmy uczące",
        correct: false,
      },
      {
        text: "wybiera się losowo przykłady wg strategii bootstrapowych",
        correct: false,
      },
    ],
  },
  {
    text: "Przykład adwersarzowy to przykład:",
    answers: [
      {
        text: "skonstruowany w celu wywołania nieprawidłowej odpowiedzi modelu",
        correct: true,
      },
      {
        text: "skonstruowany w celu wywołania sprzeciwu modelu",
        correct: false,
      },
      { text: "szczególnie trudny do zaklasyfikowania", correct: false },
      {
        text: "który może być tak przekształcony aby wywołać nieprawidłową odpowiedź modelu",
        correct: false,
      },
    ],
  },
  {
    text: "Proszę obliczyć miarę czułości (ang. sensitivity dla klasy D1) na podstawie podanej macierzy pomyłek.",
    answers: [{ text: "0.67", correct: true }],
  },
  {
    text: "Tzw. „Cost-complexity approach” w indukcji drzew jest wykorzystywane do:",
    answers: [
      {
        text: "Uczenia się oszczędnego z uwagi na zużycie czasu obliczeń",
        correct: false,
      },
      {
        text: "Wprowadzenie kosztów użycia poszczególnych atrybutów do korekcji miary entropii",
        correct: false,
      },
      {
        text: "Uwzględnienia funkcji kosztu pomyłek w obliczeniach warunków podziału w węzłach",
        correct: false,
      },
      {
        text: "Wykonania redukcji rozmiarów drzewa z sumą ważoną kryteriów minimalizacji błędu klasyfikacji oraz rozmiaru drzewa",
        correct: true,
      },
    ],
  },
  {
    text: "Miara entropii informacji stosowana w indukcyjnym uczeniu się z przykładów w przypadku klasyfikacji binarnej przyjmuje wartości:",
    answers: [
      { text: "żadna z odpowiedzi nie jest prawdziwa", correct: false },
      { text: "z przedziału [0, 1]", correct: true },
      { text: "dowolne", correct: false },
      { text: "większa od 1", correct: false },
      {
        text: "z przedziału [0, 2^k], gdzie k jest liczbą klas",
        correct: false,
      },
    ],
  },
  {
    text: "Sploty o kernelach/maskach o rozmiarach 1x1 stosuje się w sieciach neuronowych najczęściej w celu:",
    answers: [
      {
        text: "zmniejszenia liczby kanałów w tensorze wyjściowym",
        correct: true,
      },
      {
        text: "zmniejszenia liczby kanałów w tensorze wejściowym",
        correct: false,
      },
      { text: "zwiększenia rozdzielczości obrazu", correct: false },
      { text: "zmniejszenia rozdzielczości obrazu", correct: false },
      {
        text: "zwiększenia liczby kanałów w tensorze wejściowym",
        correct: false,
      },
      {
        text: "zwiększenia liczby kanałów w tensorze wyjściowym",
        correct: false,
      },
    ],
  },
  {
    text: "Twierdzenie Cybenki o uniwersalnej aproksymacji dotyczy:",
    answers: [
      {
        text: "sieci neuronowej złożonej z 3 warstw i klasy funkcji monotonicznych",
        correct: false,
      },
      {
        text: "sieci neuronowej złożonej z 2 warstw i dowolnej klasy funkcji",
        correct: false,
      },
      {
        text: "pojedynczego neuronu i klasy funkcji monotonicznych",
        correct: false,
      },
      {
        text: "dowolnej sieci neuronowej i dowolnej klasy funkcji",
        correct: false,
      },
      {
        text: "sieci neuronowej złożonej z 2 warstw i klasy funkcji monotonicznych",
        correct: true,
      },
      {
        text: "sieci neuronowej złożonej z 3 warstw i dowolnej klasy funkcji",
        correct: false,
      },
    ],
  },
  {
    text: "Ile węzłów i liści będzie miało drzewo wyindukowane dla zbioru uczącego, którego wszystkie przykłady należą do jednej klasy?",
    answers: [
      { text: "1", correct: true },
      { text: "2", correct: false },
      { text: "0", correct: false },
      { text: "co najmniej 3", correct: false },
    ],
  },
  {
    text: "Metoda analizy dyskryminacyjnej:",
    answers: [
      {
        text: "Opiera się na minimalizacji różnicy rzutów wartości średnich w klasach oraz minimalizacji odpowiednio przekształconej macierzy kowariancji",
        correct: false,
      },
      { text: "jest odmianą algorytmu analizy skupisk", correct: false },
      {
        text: "w wersji zaproponowanej przez R. Fishera automatycznie tworzy liniową płaszczyznę separującą",
        correct: true,
      },
      {
        text: "Maksymalizuje tzw. margines decyzyjny po to aby przybliżyć granicę decyzyjną",
        correct: false,
      },
    ],
  },
  {
    text: "Autoenkoder wariacyjny różni się od zwykłego następującymi cechami:",
    answers: [
      { text: "liczbą wejść dekodera", correct: false },
      {
        text: "randomizacją sygnału przekazywanego z enkodera do dekodera",
        correct: true,
      },
      { text: "sposobem obliczania błędu rekonstrukcji", correct: false },
      { text: "funkcją straty", correct: true },
      { text: "sposobem prezentowania przykładów wejściowych", correct: false },
    ],
  },
  {
    text: "Pole receptorowe pojedynczego unitu w sieci neuronowej składającej się z 3 warstw splotowych o wielkościach kerneli 3x3, 5x5, 1x1 przy stride równym 1 i bez poolingu ma wymiar:",
    answers: [
      { text: "7x7", correct: true },
      { text: "9x9", correct: false },
      { text: "6x6", correct: false },
      { text: "3x3", correct: false },
      { text: "1x1", correct: false },
      { text: "8x8", correct: false },
    ],
  },
  {
    text: "Wariacyjny autoenkoder różni się od zwykłego tym, że:",
    answers: [
      {
        text: "daje gwarancję, że wektory zmiennych ukrytych są unikalne dla wszystkich przypadków",
        correct: false,
      },
      {
        text: "nauczone wektory zmiennych ukrytych rozłożone są równomiernie po całej przestrzeni",
        correct: false,
      },
      {
        text: "wariancja wskazań autoenkodera wykorzystywana jest do uczenia sieci",
        correct: false,
      },
      {
        text: "uczony jest rozkład prawdopodobieństwa, który wykorzystywany jest do generowania wektora ukrytych zmiennych",
        correct: true,
      },
    ],
  },
  {
    text: "Zaletą funkcji aktywacji ReLU jest:",
    answers: [
      { text: "ściskanie rezultatu w przedziale [0,1]", correct: false },
      {
        text: "możliwość wykorzystania algorytmu wstecznej propagacji błędu",
        correct: false,
      },
      {
        text: "niezerowa pochodna dla dowolnego argumentu dodatniego",
        correct: true,
      },
      { text: "łatwość inicjalizacji parametrów", correct: false },
    ],
  },
  {
    text: "Reguła delta dla neuronu nieliniowego o wektorze parametrów w, funkcji aktywacji f, aktywacji z i błędzie delta ma postać:",
    answers: [
      { text: "w ← w - ηδx df/dz", correct: true },
      { text: "w ← w + ηδx", correct: false },
      { text: "w ← w + ηδ df/dz", correct: false },
      { text: "w ← w - ηδ df/dz", correct: false },
    ],
  },
  {
    text: "Pojedyncza jednostka splotowa o jądrze 3x5, 4 kanałach wejściowych, stride=2 i padding=3 ma liczbę parametrów:",
    answers: [
      { text: "45", correct: false },
      { text: "61", correct: true },
      { text: "60", correct: false },
      { text: "121", correct: false },
      { text: "46", correct: false },
      { text: "120", correct: false },
    ],
  },
  {
    text: "Składanie ze sobą warstw liniowych jest dyskusyjne, ponieważ:",
    answers: [
      {
        text: "złożenie operacji liniowych jest operacją liniową",
        correct: true,
      },
      {
        text: "większość problemów rzeczywistych jest liniowo separowalna",
        correct: false,
      },
      {
        text: "prowadzi do niepotrzebnego wzrostu liczby parametrów modelu",
        correct: false,
      },
      {
        text: "większość problemów rzeczywistych nie jest liniowo separowalna",
        correct: false,
      },
    ],
  },
  {
    text: "Zbiór walidacyjny wykorzystywany jest w uczeniu sieci neuronowych do:",
    answers: [
      { text: "przerywania uczenia w przypadku przeuczenia", correct: true },
      { text: "żadna z pozostałych odpowiedzi", correct: false },
      { text: "efektywniejszego liczenia gradientu", correct: false },
      { text: "sprawdzania poprawności implementacji", correct: false },
      { text: "testowania finalnej jakości modelu", correct: false },
    ],
  },
  {
    text: "Technikę oceny krzyżowej (k-fold cross validation) stosuje się gdy:",
    answers: [
      {
        text: "liczba przykładów jest większa niż rozmiar małej statystycznej próby",
        correct: false,
      },
      {
        text: "liczba przykładów uczących jest większa niż 100 a mniejsza niż dziesiątki tysięcy",
        correct: true,
      },
      { text: "liczba atrybutów jest równa k", correct: false },
      {
        text: "liczba przykładów jest rzędu wielu tysięcy przykładów",
        correct: false,
      },
    ],
  },
  {
    text: "Główną przeszkodą w uczeniu modeli głębokich jest/było:",
    answers: [
      { text: "zjawisko zanikających gradientów", correct: true },
      { text: "ograniczona moc obliczeniowa", correct: false },
      { text: "ograniczenia pamięciowe", correct: false },
      { text: "problem klątwy wymiarowości", correct: false },
      { text: "brak odpowiedniej inicjalizacji", correct: false },
    ],
  },
  {
    text: "Autoenkodery rozwiązujące problem autoasocjacji charakteryzuje to, że:",
    answers: [
      {
        text: "rekurencyjnie używają wektora ukrytego jako wejścia",
        correct: false,
      },
      {
        text: "oryginalne dane są najpierw reprezentowane jako pewien wektor cech, a następnie odtwarzane",
        correct: true,
      },
      {
        text: "oryginalne przypadki uczące są zapamiętywane w wektorze zmiennych ukrytych",
        correct: false,
      },
      {
        text: "porównują wektor ukryty z wejściem",
        correct: false,
      },
      {
        text: "do ich uczenia nie można użyć wstecznej propagacji błędu",
        correct: false,
      },
    ],
  },
  {
    text: "Funkcja straty typowo wykorzystywana w zadaniach klasyfikacji to:",
    answers: [
      { text: "błąd średniokwadratowy", correct: false },
      { text: "średni błąd absolutny", correct: false },
      { text: "entropia krzyżowa", correct: true },
      { text: "strata zerojedynkowa", correct: false },
      { text: "trafność klasyfikacji", correct: false },
    ],
  },
  {
    text: "Ściskające funkcje aktywacji to między innymi:",
    answers: [
      { text: "Leaky ReLU i ReLU", correct: false },
      { text: "funkcja liniowa i tanh", correct: false },
      { text: "sigmoidalna i ReLU", correct: false },
      { text: "sigmoidalna i tangens hiperboliczny", correct: true },
    ],
  },
  {
    text: "Uczenie modeli sieci neuronowych wymaga obliczenia gradientu:",
    answers: [
      { text: "hiperparametrów względem parametrów", correct: false },
      { text: "parametrów względem funkcji straty", correct: false },
      { text: "funkcji straty względem parametrów modelu", correct: true },
      { text: "funkcji straty względem wejść modelu", correct: false },
    ],
  },
  {
    text: "Dropout to technika regularyzacji charakteryzująca się:",
    answers: [
      {
        text: "stochastycznym usuwaniem neuronów podczas uczenia i testowania",
        correct: false,
      },
      {
        text: "stochastycznym usuwaniem neuronów podczas uczenia i zmniejszaniem amplitudy wyjść podczas testowania",
        correct: true,
      },
      {
        text: "stochastycznym usuwaniem neuronów podczas testowania",
        correct: false,
      },
      {
        text: "stochastycznym usuwaniem neuronów podczas uczenia i zwiększaniem amplitudy wyjść podczas testowania",
        correct: false,
      },
    ],
  },
  {
    text: "Klasyfikowanie nowego obiektu przy użyciu reguł wygenerowanych algorytmem LEM2 odbywa się na podstawie:",
    answers: [
      { text: "strategii list priorytetowej reguł", correct: false },
      {
        text: "najdokładniejszej reguły dopasowanej do obiektu",
        correct: false,
      },
      { text: "żadna z odpowiedzi", correct: false },
      {
        text: "głosowania wsparciami wszystkich dopasowanych reguł",
        correct: true,
      },
      {
        text: "najsilniejszej reguły dopasowanej do obiektu",
        correct: false,
      },
    ],
  },
  {
    text: "Klasyfikowanie nowego obiektu przy użyciu reguł wygenerowanych ze struktury drzewa C4.5 odbywa się na podstawie:",
    answers: [
      { text: "strategii list priorytetowej reguł", correct: true },
      {
        text: "ostatniej dopasowanej reguły",
        correct: false,
      },
      {
        text: "zbioru wszystkich dopasowanych reguł",
        correct: false,
      },
      { text: "żadna z odpowiedzi", correct: false },
      {
        text: "najsilniejszej dopasowanej reguły",
        correct: false,
      },
    ],
  },
  {
    text: "Jakie przykłady uczące są zapamiętywane w algorytmie IBL3?",
    answers: [
      {
        text: "posiadające statystycznie znaczącą wysoką wartość rekordu klasyfikacyjnego",
        correct: true,
      },
      { text: "te, które są poprawnie klasyfikowane", correct: false },
      { text: "wszystkie", correct: false },
      { text: "żadna z odpowiedzi", correct: false },
      {
        text: "te, dla których podczas uczenia popełniane są błędy",
        correct: false,
      },
    ],
  },
  {
    text: "Kryterium gain-ratio używa się w indukcji drzew i reguł decyzyjnych w następujących sytuacjach:",
    answers: [
      {
        text: "Jest to zastępcze kryterium podziału dla algorytmu CART",
        correct: false,
      },
      {
        text: "Stosowana jest w trakcie dyskretyzacji atrybutów liczbowych",
        correct: false,
      },
      {
        text: "Nieprawda - nie jest wykorzystywane w indukcji drzew",
        correct: false,
      },
      {
        text: "Pozwala na lepsze uwzględnienie atrybutów o zróżnicowanych dziedzinach",
        correct: true,
      },
    ],
  },
  {
    text: "Warunkiem zatrzymania algorytmu k-średnich jest:",
    answers: [
      {
        text: "zakończenie dyskretyzacji atrybutów liczbowych",
        correct: false,
      },
      { text: "utworzenie pełnego drzewa skupień", correct: false },
      {
        text: "optymalizacja wartości k - tzn. jej obliczenie",
        correct: false,
      },
      {
        text: "osiągnięcie stabilizacji zawartości przykładów wewnątrz skupień",
        correct: true,
      },
    ],
  },
  {
    text: "Autodiff to żargonowe określenie na:",
    answers: [
      {
        text: "techniki automatycznego różniczkowania wykorzystywane w uczeniu głębokim",
        correct: true,
      },
      {
        text: "funkcję straty wykorzystywaną często w modelach uczonych przez autoasocjację",
        correct: false,
      },
      {
        text: "najbardziej popularną klasę algorytmów wstecznej propagacji błędu",
        correct: false,
      },
    ],
  },
  {
    text: "Estymacja parametrów w regresji logistycznej jest dokonywana poprzez:",
    answers: [
      {
        text: "analityczne rozwiązanie metody najmniejszych kwadratów",
        correct: false,
      },
      { text: "metodę estymacji największej wiarygodności", correct: true },
      {
        text: "algorytm spadku gradientu błędu średniokwadratowego",
        correct: false,
      },
      { text: "algorytm Larossa", correct: false },
    ],
  },
  {
    text: "Funkcje straty dla typowych modeli neuronowych z dużą liczbą parametrów mają zazwyczaj:",
    answers: [
      {
        text: "więcej lokalnych ekstremów niż punktów siodłowych",
        correct: false,
      },
      {
        text: "więcej minimów globalnych niż minimów lokalnych",
        correct: false,
      },
      {
        text: "więcej punktów siodłowych niż lokalnych ekstremów",
        correct: true,
      },
      {
        text: "więcej minimów lokalnych niż maksimów lokalnych",
        correct: false,
      },
    ],
  },
  {
    text: "Selekcję zmiennych w modelu regresji liniowej można dokonać poprzez:",
    answers: [
      { text: "Obliczając przedział ufności predykcji", correct: false },
      {
        text: "Procedurę krokowego wyboru kontrolowanego przez obliczenie statystyki F",
        correct: true,
      },
      {
        text: "Wykorzystanie wskaźnika Lorenza do oceny każdej zmiennej niezależnej",
        correct: false,
      },
      {
        text: "Na podstawie analizy wartości lokalnego testu t w diagnostyce modelu",
        correct: true,
      },
    ],
  },
  {
    text: "Czy algorytm k-NN z euklidesową miarą odległości może być użyty bezpośrednio do klasyfikacji danych, gdzie osoby opisane są przez 3 atrybuty liczbowe: rozmiar buta, waga, roczne zarobki i 1 decyzyjny wskazujący klasę?",
    answers: [
      {
        text: "nie, należy dokonać normalizacji zakresu atrybutów",
        correct: true,
      },
      { text: "tak, jest to typowy problem", correct: false },
      { text: "nie, gdyż liczba atrybutów jest zbyt mała", correct: false },
      { text: "nie, gdyż należy użyć odległości miejskiej", correct: false },
    ],
  },
  {
    text: "Reguła delta dla unitu nieliniowego o wektorze parametrów w, funkcji aktywacji f, aktywacji e, który w odpowiedzi na wektor wejść x popełnił błąd delta, ma następującą postać:",
    answers: [
      { text: "w <- w - eta delta x df/de", correct: true },
      { text: "w <- w + eta delta f(e) df/de", correct: false },
      { text: "w <- w + eta delta x df/de", correct: false },
      { text: "w <- w - eta f(x) delta/de", correct: false },
      { text: "w <- w - eta delta x", correct: false },
    ],
  },
  {
    text: "W przypadku uczenia nienadzorowanego (np. grupowanie) do selekcji atrybutów NIE można użyć:",
    answers: [
      { text: "usuwania atrybutów skorelowanych", correct: false },
      { text: "usuwania atrybutów z niską wariancją", correct: false },
      { text: "tworzenia nowych atrybutów np. metodą PCA", correct: false },
      {
        text: "usuwania atrybutów z niską wartością information gain",
        correct: true,
      },
    ],
  },
  {
    text: "Zespół klasyfikatorów bagging, niech liczba składowych klasyfikatorów będzie T:",
    answers: [
      { text: "jest oparty na losowym wyborze przykładów", correct: true },
      {
        text: "agreguje predykcje klasyfikatorów składowych przez głosowanie",
        correct: true,
      },
      { text: "buduje się rozwiązanie meta-klasyfikatora", correct: false },
      {
        text: "wykorzystuje losowanie bootstrapowe przykładów do T prób uczących",
        correct: true,
      },
    ],
  },
  {
    text: "Bramka zapominająca w standardowej architekturze LSTM sieci rekurencyjnej:",
    answers: [
      {
        text: "jest siecią neuronową z funkcją aktywacji będącą sigmoidalną, której celem jest selektywne wybranie elementów, które pozostaną w pamięci",
        correct: true,
      },
      {
        text: "jest siecią neuronową z funkcją aktywacji będącą tangensem hiperbolicznym, której celem jest selektywne wybranie elementów, które pozostaną w pamięci",
        correct: false,
      },
    ],
  },
  {
    text: "W standardowej architekturze LSTM rekurencyjnej sieci neuronowej:",
    answers: [
      {
        text: "pamięć jest najpierw filtrowana przez operację mnożenia po elementach wektora liczb z przedziału [-1, 1], a potem modyfikowana poprzez operację dodawania wektora z elementami z przedziału [-1, 1]",
        correct: false,
      },
      {
        text: "pamięć jest najpierw filtrowana przez operację mnożenia po elementach wektora liczb z przedziału [0, 1], a potem modyfikowana poprzez operację dodawania wektora z elementami z przedziału [0, 1]",
        correct: false,
      },
      {
        text: "pamięć jest najpierw filtrowana przez operację dodawania wektora liczb z przedziału [0, 1], a potem modyfikowana poprzez operację mnożenia po elementach wektora z elementami z przedziału [0, 1]",
        correct: false,
      },
      {
        text: "pamięć jest najpierw filtrowana przez operację mnożenia po elementach wektora liczb z przedziału [0, 1], a potem modyfikowana poprzez operację dodawania wektora z elementami z przedziału [-1, 1]",
        correct: true,
      },
      {
        text: "pamięć jest najpierw filtrowana przez operację dodawania wektora liczb z przedziału [-1, 1], a potem modyfikowana poprzez dodawanie wektora z elementami z przedziału [0, 1]",
        correct: false,
      },
    ],
  },
];
