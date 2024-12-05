require_relative "../app/models/dino"
require_relative "../app/models/ticket"
require_relative "../app/models/user"
require_relative "../app/models/users_verified"

User.destroy_all
Ticket.destroy_all
Users_verified.destroy_all
Dino.destroy_all

Dino.create_multiple_dino([{
  name: "Нигерзавр (Nigersaurus)",
  description: "Нигерзавр — род завроподовых динозавров из семейства реббахизаврид, обитавших на Земле в середине мелового периода. Открыт в районе Гадуфауа, формации Эльрхаз на территории Республики Нигер. Впервые ископаемые остатки описаны в 1976 году, название дано лишь в 1999-м.",
  image: "https://upload.wikimedia.org/wikipedia/commons/thumb/c/c8/Nigersaurus_model_aus.jpg/220px-Nigersaurus_model_aus.jpg",
  allowed: true
},
{
  name: "Стегозавр (Stegosaurus)",
  description: "Стегозавры были крупнейшими представителями своего инфраотряда, включавшего также роды Kentrosaurus и Huayangosaurus. Их максимальная длина составляла 9 метров (S. armatus), высота — 4 метра. Грегори Пол оценил длину вида Stegosaurus ungulatus в 7 м и вес в 3,8 тонн. Мозг динозавра был не больше, чем у собаки: при весе животного в 2 тонны его мозг весил лишь 70 граммов. ",
  image: "https://upload.wikimedia.org/wikipedia/commons/thumb/5/5f/Stegosaurus_stenops_Life_Reconstruction_%28flipped%29.png/1920px-Stegosaurus_stenops_Life_Reconstruction_%28flipped%29.png",
  allowed: true
},
{
  name: "Тиранноза́вр (Tyrannosaurus)",
  description: "Tyrannosaurus rex был одним из самых крупных наземных хищников всех времён. Длина голотипа (AMNH 502) оценивается в 10,6 м, а высота до бедра — 3,4 м. Самый большой из относительно полных скелетов, RSM P2523.8 по прозвищу «Скотти» (Scotty), был обнаружен в 1991 году в канадской провинции Саскачеван. По оценкам специалистов из Университета Альберты, этот чрезвычайно массивный для своего вида экземпляр достигал в длину 13 метров и весил около 8,8 тонн. ",
  image: "https://encrypted-tbn3.gstatic.com/images?q=tbn:ANd9GcTh_7nnW56nl9JqdAvSu6frDAMdV9oTRlQkmeocdbeJtqwMaPz1",
  allowed: true
},
{
    name: "Велоцира́птор (Velociraptor)",
  description: "Велоцираптор был небольшим динозавром, до 1,5 м в длину, 40-70 см в высоту и весил до 20 кг, хотя существует мнение, что он мог весить до 24 кг. Подобно большинству тероподов, велоцираптор обладал четырьмя пальцами на задних конечностях, из которых один был недоразвит и не участвовал в ходьбе, и (как и тероподы) ступал на три пальца. Дромеозавриды, в том числе велоцираптор, использовали только два: третий и четвёртый. На втором находился большой сильно изогнутый коготь, выраставший до 67 мм в длину (по внешнему краю). Он ранее считался их основным оружием для умерщвления и разрывания жертв.",
  image: "https://upload.wikimedia.org/wikipedia/commons/thumb/e/ee/Fred_Wierum_Velociraptor.png/640px-Fred_Wierum_Velociraptor.png",
  allowed: true
},
{
    name: "Пивозавр (Любитель хмельного)",
    description: "Пивозавр (Lat. Cervisia saurus) — гипотетическое ископаемое млекопитающее, предположительно обитавшее в мезозойской эре. Отличался развитым ферментативным аппаратом, способным перерабатывать растительные сахара в алкогольные напитки.
",
  image: "https://goods-photos.static1-sima-land.com/items/7059527/1/700-nw.jpg",
  allowed: true
},
{
    name: "Дилофозавр (Dilophosaurus)",
    description: "Дилофозавры были одними из ранних крупных хищных теропод. Они достигали длины 7 метров и массы около 400 килограммовПерейти к разделу «#Описание». Череп дилофозавра нёс пару длинных, тонких гребней, ориентированных в продольном направлении. Верхняя челюсть имела характерный «излом», называемый подноздревой щелью, который являлся причиной диастемы — разрыва в зубном рядуПерейти к разделу «#Череп».",
    image: "https://image-service.zaonce.net/eyJidWNrZXQiOiJmcm9udGllci1jbXMiLCJrZXkiOiIyMDIxLTExL2RpbG9waG9zYXVydXNfMzA0OTExLnBuZyIsImVkaXRzIjp7InJlc2l6ZSI6eyJ3aWR0aCI6NDAwfX19",
  allowed: true
},
{
    name: "Диплодо́к (Diplodocus)",
    description: "Диплодок считается одним из наиболее легко идентифицируемых видов динозавров. Является крупнейшим из динозавров, известных по полным скелетам. Большие размеры диплодока, вероятно, были сдерживающим фактором для хищников того времени — аллозавра и цератозавра, ископаемые остатки которых найдены в тех же слоях, что и остатки диплодока.",
  image: "https://encrypted-tbn2.gstatic.com/images?q=tbn:ANd9GcSu9ADa02BaQgwn1fdVMInq2U1oiTHj5QSscl1dLLJNcEHoqVjnpM6ajqaon5fhGh-2Rs7aDNWlwh23uscmg4WEq7p7zViXbuZQQ7IlXMM",
  allowed: true
},
{
  name: "Курица (Gallus gallus domesticus)",
  description: "Gallus gallus domesticus, широко известная как обыкновенная курица, является тероподным динозавром из мелового периода. Этот птицеподобный динозавр демонстрирует множество адаптивных черт, указывающих на его эволюционное происхождение. С двуногой стойкой и перьевым покровом, G. gallus domesticus демонстрирует значительные эволюционные достижения как в полёте, так и в терморегуляции. Его клюв, лишённый зубов, адаптирован для разнообразного всеядного рациона, в то время как крепкие задние конечности свидетельствуют о высоких наземных способностях. Вид проявляет сложное социальное поведение и вокализацию, отражающие развитое нервное развитие. Ископаемые свидетельства указывают на наличие у G. gallus domesticus сложной дыхательной системы, подобной современной, поддерживающей высокие метаболические потребности. Этот вид предоставляет важные сведения об эволюционном переходе от нептичьих динозавров к современным птицам.",
  image: "https://hi-news.ru/wp-content/uploads/2020/06/chicken_home_image_one-750x558.jpg",
  allowed: true
}])
