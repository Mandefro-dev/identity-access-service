import { VERIFICATION_EMAIL_TEMPLATE } from "./emailTemplate.js";
import { mailtrapClient, sender } from "./mailtrap.config.js";

export const sendverificationEmail = async (email, verificationToken) => {
  const recipients = [
    {
      email,
    },
  ];

  try {
    const response = await mailtrapClient.send({
      from: sender,

      to: recipients,
      subject: "Verify your Email.",
      html: VERIFICATION_EMAIL_TEMPLATE.replace(
        "{verificationCode}",
        verificationToken,
      ),
      category: "Email verification.",
    });
    console.log("Email sent succesfully", response);
  } catch (error) {
    console.error(`Error sending verification ${error}`);
    throw new Error(`Error sending verification email: ${error}`);
  }
};
