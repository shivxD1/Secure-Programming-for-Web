const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
    service: 'Mailgun',
    auth: {
        user: "postmaster@sandbox158b67c13cc1442b86fd605b7fc48f7a.mailgun.org",
        pass: 'e9a5ed1b76ae3f32eeee5331f3a696aa-48d7d97c-f6c3e78c'
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
