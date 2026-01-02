const optMailTemplate = (username, otp) => {
    return `
    <div style="font-family: Arial, sans-serif; line-height: 1.5;">
      <h2>Hello ${username},</h2>
      <p>Your email verification code is:</p>
      <h1 style="letter-spacing: 5px;">${otp}</h1>
      <p>This code will expire in <b>10 minutes</b>.</p>
      <p>If you didn’t request this, please ignore this email.</p>
    </div>
  `;
};

export default optMailTemplate;