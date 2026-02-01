import {
  PASSWORD_RESET_REQUEST_TEMPLATE,
  PASSWORD_RESET_SUCCESS_TEMPLATE,
  VERIFICATION_EMAIL_TEMPLATE,
} from "./emailTemplate.js";
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

export const sendWelcomeEmail = async (email, name) => {
  const recipients = [{ email }];

  try {
    const response = await mailtrapClient.send({
      from: sender,
      to: recipients,
      template_uuid: "9df53b95-e782-4aee-b690-0b22ce4e01e3",
      template_variables: {
        company_info_name: "Auth company",
        name: name,
      },
    });

    console.log("Welcome Email sent welcome successfully", response);
  } catch (error) {
    throw new Error(error);
  }
};
export const sendPasswordResetEmail = async (email, resetUrl) => {
  const recipients = [{ email }];
  try {
    const response = await mailtrapClient.send({
      from: sender,
      to: recipients,
      subject: "Reset your password.",
      html: PASSWORD_RESET_REQUEST_TEMPLATE.replace("{resetURL}", resetUrl),
      category: "Password Reset",
    });
    console.log("Password Reset link sent successfully.", response);
  } catch (error) {
    console.log("Error sensing resetpassword email", error.message);
    throw new Error(`Error sending password email reset email ${error}`);
  }
};

export const sendPasswordResetSuccessEmail = async (email) => {
  const recipients = [{ email }];

  try {
    const response = await mailtrapClient.send({
      from: sender,
      to: recipients,
      subject: "Reset password successfull.",
      html: PASSWORD_RESET_SUCCESS_TEMPLATE,
      category: "Password Reset",
    });
    console.log("Password reset success email sent successfully.", response);
  } catch (error) {
    console.log("Error sending reset password success email", error.message);
    throw new Error(`Error sendig password reset succes email ${error}`);
  }
};
