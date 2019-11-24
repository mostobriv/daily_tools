
struct std::vector {
  void    *start;
  void    *end;
  void    *end_cap;
}

struct std::string {
  union {
    struct {
      char[16] str;
      size_t  length;
    } short_str;
    struct {
      char*   data;
      size_t  length;
      size_t  capacity;
    } long_str;
  }
}
