import ImageKit from "imagekit";

const imagekit = new ImageKit({
  publicKey: process.env.IMAGEKIT_PUBLIC_KEY,
  privateKey: process.env.IMAGEKIT_PRIVATE_KEY,
  urlEndpoint: process.env.IMAGEKIT_URL_ENDPOINT,
});

const uploadImage = async (file) => {
  try {
    const result = await imagekit.upload({
      file: file.buffer.toString("base64"), // REQUIRED
      fileName: file.originalname,
      folder: "/uploads",
      useUniqueFileName: true,
    });

    return result;
  } catch (error) {
    console.error("ImageKit upload failed:", error);
    throw error;
  }
};

export default uploadImage;
