import mongoose from "mongoose";

const postSchmea = new mongoose.Schema(
  {},
  {
    timestamps: true,
  },
);

export const Post = mongoose.model("Post", postSchmea);
