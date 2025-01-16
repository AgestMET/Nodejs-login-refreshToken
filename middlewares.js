import jwt from 'jsonwebtoken';

// Eğer doğrulama gerçekleşmişse yani token varsa next metodu ile işlemin devam etmesini sağlayacağız
// Token, gelen istekte(req) authorization header'ı içrerisinde gönderiliyor
export const authMiddleware = (req, res, next) => {
    // Gelen token req'in(isteğin) headers'ının altındaki authorization'ın içinde "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImF..." şeklinde geliyor
    // Buradaki Bearer tokenin tipi, geri kalan kısım ise token'in değeri
    // split metodu ile bu gelen token bilgisini arasındaki boşluk ile diziye çevirip iki parçaya ayırıyoruz ve ikinci elemanını([1]) token değişkenine atıyoruz
    const token = req.headers['authorization']?.split(' ')[1]

    // Eğer token yoksa(undefined) 401 status kodunu(forbidden, yasak) döneceğiz
    if(!token) 
        return res.status(401).json({ message: "Please log in" });
    // gelen token değeri(token) ile .env dosyasının içerisindekli secret(process.env.ACCESS_TOKEN_SECRET) arasında doğrulama yapacak ve geçerli ise
    //  -gelen token'in payload(email, username) kısmını, ikinci parametre olan payload'a atayacak
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
        if(err) {
            console.log("verify error = ", err);
            // 400 -> bad request
            return res.status(400).json(err);
        }
        // Gelen req'in altına tokenPayload adında yeni bir field(alan) açtık ve buna verify'dan gelen payload bilgisini(gelen token'in payload'ı(email, username)) atadık
        req.tokenPayload = payload;
        // Her şey başarılı ise next metodu çalışacak yani index.js'deki app.get("/animals", authMiddleware) yapısının içine girebilirsin
        next()
    })
}