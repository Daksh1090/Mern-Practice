import transporter from "./config.js";


const sendmail = async ({ to, subject, html }) => {
    const mailOptions = {
        from: `MERN Auth <${process.env.GOOGLE_APP_EMAIL}>`,
        to,
        subject,
        html,
    };

    await transporter.sendMail(mailOptions);
};

export default sendmail;
