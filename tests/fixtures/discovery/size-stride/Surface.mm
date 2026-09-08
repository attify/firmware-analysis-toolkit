class Surface {
 public:
  void UploadRegion(unsigned width,
                    unsigned height,
                    unsigned row_pitch,
                    unsigned depth_pitch) {
    unsigned buffer = MakeBuffer(width * height);
    CopyRegion(buffer, row_pitch, depth_pitch);
  }

 private:
  unsigned MakeBuffer(unsigned size) { return size; }

  void CopyRegion(unsigned buffer, unsigned row_pitch, unsigned depth_pitch) {
    last_copy_size_ = buffer + row_pitch + depth_pitch;
  }

  unsigned last_copy_size_ = 0;
};
