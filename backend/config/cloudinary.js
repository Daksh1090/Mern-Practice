import { v2 as cloudinary } from "cloudinary";
import fs from "fs/promises";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const fileUploadOnCloudinary = async (filePath) => {
  if (!filePath) return null;

  try {
    const response = await cloudinary.uploader.upload(filePath, {
     resource_type: "image",
    folder: "uploads/images",
    });

    // Remove file only after successful upload
    await fs.unlink(filePath);

    return response;
  } catch (error) {
    console.error("Cloudinary upload failed:", error);

    // Optional: still cleanup file if it exists
    try {
      await fs.unlink(filePath);
    } catch (_) {}

    throw error; // let controller handle it
  }
};

export default fileUploadOnCloudinary;
