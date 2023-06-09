# SHA-1 (classic+boosted)

Тут було реалізовано алгоритм гешування даних SHA-1 та перевірка власної реалізації на правильність через порівняння результатів з бібліотечною реалізацією. Після порівняння було створено поліпшену версію алгоритму, що трохи "виграє" за часом у бібліотечної :)

Код у sha1.rs реалізує звичайний алгоритм SHA-1 для обчислення хеш-суми повідомлення. Використовуються дві реалізації: одна власна (custom_hash), а інша з використанням бібліотеки crypto (library_hash).
1. Визначено константу BLOCK_SIZE, яка визначає розмір блоку у байтах.
2. Функція pad_message додає необхідні біти заповнення до повідомлення для забезпечення кратності розміру блоку. Повідомлення конвертується в байтовий вектор padded, де додається '1' бітова одиниця та необхідна кількість '0' бітів. На кінці додається довжина повідомлення у бітах у форматі 64-бітного цілого числа у порядку big-endian.
3. Функція hash_sha1 обчислює хеш-суму повідомлення з використанням SHA-1. Вона розбиває повідомлення на блоки та застосовує ітераційні перетворення SHA-1 для кожного блоку. Після обробки всіх блоків, значення хешу повертаються у вигляді масиву байтів.
4. Функція main є точкою входу в програму. Вона виконує обчислення хеш-суми для повідомлення як за допомогою власної реалізації, так і за допомогою бібліотеки crypto. Результати обох обчислень порівнюються, і виводяться на екран, разом з часом виконання кожного обчислення:

![image](https://github.com/soffije/hash-lib/assets/93443981/9ddde661-3584-4882-8bd2-c7687dde112b)
![image](https://github.com/soffije/hash-lib/assets/93443981/dbeab3ad-ec0b-47b0-be12-3a9e86cf1399)

Цей sha1-boosted.rs код реалізує полцпшений алгоритм SHA-1 для обчислення хеш-значення повідомлення.
Основні функції коду:
1. Функція pad_message: Ця функція додає доповнення до повідомлення для вирівнювання його до блоку фіксованого розміру. Вона приймає повідомлення message у вигляді байтового масиву і повертає вирівняне повідомлення у вигляді вектора байтів.
2. Функція hash_sha1_block: Ця функція обчислює хеш одного блоку повідомлення. Вона приймає блок повідомлення block у вигляді байтового масиву і повертає хеш у вигляді масиву з 20 байтів.
3. Функція hash_sha1: Ця функція обчислює кінцевий хеш повідомлення, розбиваючи його на блоки та обчислюючи хеш кожного блоку. Вона приймає повідомлення message у вигляді байтового масиву і повертає кінцевий хеш у вигляді масиву з 20 байтів.
4. Функція main(): Це головна функція програми. Вона містить приклад використання обчислення хешу SHA-1 для заданого повідомлення. У цій функції створюється прикладне повідомлення message, обчислюються хеші за допомогою власної функції та бібліотечної функції, порівнюються отримані хеші та виводяться результати на екран:

![image](https://github.com/soffije/hash-lib/assets/93443981/182cf79a-f962-4a26-80bc-9d34794bc967)
![image](https://github.com/soffije/hash-lib/assets/93443981/520bebf1-1a45-4cc5-ab11-cd158a432dc0)

Ці два коди реалізують обчислення хеш-функції SHA-1 для заданого повідомлення, але другий код використовує бібліотеку `rayon` для паралельного обчислення хешів блоків повідомлення. 
В першому коді sha1.rs хеш-функція `hash_sha1` обчислює хеш повідомлення, поділеного на блоки розміром `BLOCK_SIZE`. У циклі для кожного блоку виконується розрахунок значень хешу за алгоритмом SHA-1. Отримані хеші блоків об'єднуються в кінцевий хеш повідомлення. Цей код працює послідовно без використання паралельних обчислень.
У другому коді sha1-boosted.rs функція `hash_sha1_block` виконує обчислення хешу для окремого блоку повідомлення. Використовуючи бібліотеку `rayon`, вхідне повідомлення розділяється на блоки та паралельно обчислюється хеш кожного блоку за допомогою `par_chunks` і `map`. Після цього, отримані хеші блоків об'єднуються в кінцевий хеш повідомлення. Використання паралельних обчислень може прискорити процес обчислення хешу, особливо для великих повідомлень, де блоків багато.
Таким чином, другий код успішно(!) використовує паралельні обчислення для прискорення обчислення хешу повідомлення, що ми і спостерігаємо на рисунках.
