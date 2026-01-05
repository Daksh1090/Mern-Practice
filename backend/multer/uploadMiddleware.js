import multer from "multer";
import upload from "./upload.js";

export const uploadSingleImage = (fieldName) => {
  return (req, res, next) => {
    upload.single(fieldName)(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        return res.status(400).json({ message: err.message });
      }

      if (err) {
        return res.status(400).json({ message: err.message });
      }

      next();
    });
  };
};
