const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
    service: 'Mailgun',
    auth: {
        user: "postmaster@sandboxbb1ff095b2144971a182188e7d5a01e0.mailgun.org",
        pass: 'ff1d15b0130bb91db1edc780be5ac847-48d7d97c-1fbaacad'
    },
    secure: false,
    port: 25,
    tls: {
        rejectUnauthorized: false
    }
});

module.exports= {
    sendEmail(from,to,subject,html){
        return new Promise((resolve,reject)=>{
            transport.sendMail({from,subject,to,html},(err,info)=>{
                if(err){
                    reject(err);
                }
                resolve(info);
            });
        });
    }
}
