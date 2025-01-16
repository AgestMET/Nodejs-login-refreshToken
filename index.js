// package.json'da "type": "module" diye belirttiğimiz için bu şekilde paketleri import edebiliyoruz. Yoksa require keyword'ünü kullanmamız gerekirdi
import express from "express";
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
// import keyword'ünde from'dan sonraki kısımdaki dosya isminin sonuna .js'i yazmak zorundayız yokda import işlemi gerçekleşmiyor
import { authMiddleware } from "./middlewares.js";


// config metodu dotenv dosyasının içerisindeki ortam değişkenlerini(secretlar) kullanmamızı(expose) sağlıyor
dotenv.config()

const app = express();
// gelen isteklerde json ile çalışabilmek için json'ı ayrıştırmak için bu middleware(arayazılım)'i çağırıyoruz
app.use(express.json())

const user = {
    username: "admin",
    email: "admin@mail.com",
    password: "12345"
};

const animalsArray = [
    {
        name: "Elephant", createdAt: new Date(),
    },
    {
        name: "Lion", createdAt: new Date(),
    },
];

let refreshTokens = [];

app.get("/animals", authMiddleware, (req, res) => {
    console.log("/animals req.tokenPayload = ", req.tokenPayload);
    return res.json(animalsArray);
})

app.post("/logout", async(req, res) => {
    console.log("Array refreshTokens = ", refreshTokens);
    // eşit olmayanları bırak
    refreshTokens = refreshTokens.filter(
        (token) => token !== req.body.refreshToken
    );
    console.log("After Array refreshTokens = ", refreshTokens);
    return res.sendStatus(200);
});

// Kullanıcı bu endpointte kendi refresh tokeni ile bir istek yaparsa ve biz o tokeni doğrulayabilirsek ona yeni bir access token gönderecedğiz
app.post("/refresh", async(req, res) => {
    // req'in(gelen isteğin) bodysinde bir refresh token geliyor olmalı (postman'den)
    const { refreshToken } = req.body;

    // refresh token hiç yoksa yanlış adrese istek yapıldı demektir
    if(!refreshToken) return res.sendStatus(401);

    // gelen isteğin(req.body) içerisindeki refresh token(refreshToken), bizim yukarıda dizi şeklinde saklağımız refresh token(refreshTokens) ile aynı mı
    // res.status(401) yerine res.sendStatus(401); yazsa idik ayrıyeten json bilgisi göndermek istediğimizde node:_http_outgoing:699 -> throw new ERR_HTTP_HEADERS_SENT('set'); hatasını alırdık
    if(!refreshTokens.includes(refreshToken)) return res.status(401).json({ message: "Invalid refresh token" });

    // verify metodu gelen refresh token ile daha önce oluşturduğumuz refresh tokenimizin secret'ını karşılaştırıp doğrulayacak
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, data) => {
        if(err) {
            console.log("refresh token verify error = ", err);
            return res.status(400).json(err);
        }
        // Eğer doğrulama gerçekleşmişse yeni bir access token oluşturuyoruz
        // İlk parametre olarak kullanıcının saklamak istediğimiz verilerini verify metodundan dönen data'nın içindeki bilgilerden çektik
        const accessToken = jwt.sign({email: data.email, username: data.username}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "2m" });
        return res.status(200).json({ accessToken });
    })
})

app.post("/login", async(req, res) => {
    // req'in(gelen isteğin) bodysinde bir email password bilgisi geliyor olmalı (postman'den)
    const { email, password } = req.body;

    // gelen email ve password bilgileri yukarıda tanımladığımız databaseimizin içindeki bilgiler ile aynı mı
    if(email !== user.email || password !== user.password)
        return res.status(401).json({ message: "Information Invalid" });

    // jsonwebtoken(jwt) paketinin içerisindeki sign metodu ile bir access token oluşturuldu
    //  -Bu metot ilk parametre olarak payload yani kullanıcının saklamak istediğimiz bilgilerini alır
    //  -İkinci parametre olarak bir private key veya secret alır. bunu da önceden oluşturulan .env dosyasının içindeki ACCESS_TOKEN_SECRET tanımından çektik
    //  -Üçüncü parametre olarak da token ayarlalarını alır. expiresIn ayarı ile tokenin geçerli olacağı süreyi belirledik
    const accessToken = jwt.sign({ email: user.email, username: user.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "2m" })

    // Bu refreshToken tanımlasında secret'ı .env dosyasının içindeki REFRESH_TOKEN_SECRET tanımından çektik
    // Üçüncü parametre olarak bir şey yazmadık yani yenilenen token sonsuz süre ile var olacak sadece logout işlemi yapıldığında silinecek
    const refreshToken = jwt.sign({ email: user.email, username: user.username }, process.env.REFRESH_TOKEN_SECRET)

    refreshTokens.push(refreshToken);

    return res.status(200).json( {accessToken, refreshToken} );
})



app.listen(5000, () => { console.log("Server is ready on port 5000 !") })