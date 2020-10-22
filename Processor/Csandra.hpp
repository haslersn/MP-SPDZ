#ifndef CSANDRA_HPP_
#define CSANDRA_HPP_

#include <boost/beast/core/span.hpp>
#include <cassandra.h>
#include <chrono>
#include <string>

class CsandraError : public std::runtime_error
{
public:
  CsandraError(CassError error_code, const std::string &what_arg);
  CsandraError(CassError error_code, const char *what_arg);

  CassError error_code() const noexcept;

private:
  CassError m_error_code;
};

class CsandraResult
{
public:
  CsandraResult() noexcept = default;
  explicit CsandraResult(const CassResult *inner) noexcept;
  ~CsandraResult() noexcept;
  CsandraResult(CsandraResult &&other) noexcept;
  CsandraResult &operator=(CsandraResult &&other) noexcept;

  // This is a non-copy type in order to prevent double freeing.
  CsandraResult(const CsandraResult &) = delete;
  CsandraResult &operator=(const CsandraResult &) = delete;

  explicit operator bool() const noexcept;

  const CassResult *inner() const noexcept;

  friend void swap(CsandraResult &lhs, CsandraResult &rhs) noexcept;

private:
  const CassResult *m_inner;
};

class CsandraStatement
{
public:
  static CsandraStatement make(const char *query, size_t parameter_count);

  CsandraStatement() noexcept = default;
  explicit CsandraStatement(CassStatement *inner) noexcept;
  ~CsandraStatement() noexcept;
  CsandraStatement(CsandraStatement &&other) noexcept;
  CsandraStatement &operator=(CsandraStatement &&other) noexcept;

  // This is a non-copy type in order to prevent double freeing.
  CsandraStatement(const CsandraStatement &) = delete;
  CsandraStatement &operator=(const CsandraStatement &) = delete;

  explicit operator bool() const noexcept;

  CassStatement *inner() noexcept;
  const CassStatement *inner() const noexcept;

  void reset_parameters(size_t count);
  void add_key_index(size_t index);
  void set_keyspace(const char *keyspace);
  void set_consistency(CassConsistency consistency);
  void set_serial_consistency(CassConsistency serial_consistency);
  void bind(size_t index, nullptr_t);
  void bind_by_name(const char *name, nullptr_t);
  void bind(size_t index, int8_t value);
  void bind_by_name(const char *name, int8_t value);
  void bind(size_t index, int16_t value);
  void bind_by_name(const char *name, int16_t value);
  void bind(size_t index, int32_t value);
  void bind_by_name(const char *name, int32_t value);
  void bind(size_t index, uint32_t value);
  void bind_by_name(const char *name, uint32_t value);
  void bind(size_t index, int64_t value);
  void bind_by_name(const char *name, int64_t value);
  void bind(size_t index, float value);
  void bind_by_name(const char *name, float value);
  void bind(size_t index, double value);
  void bind_by_name(const char *name, double value);
  void bind(size_t index, bool value);
  void bind_by_name(const char *name, bool value);
  void bind(size_t index, const char *value);
  void bind_by_name(const char *name, const char *value);
  void bind(size_t index, boost::beast::span<uint8_t> value);
  void bind_by_name(const char *name, boost::beast::span<uint8_t> value);
  void bind(size_t index, CassUuid value);
  void bind_by_name(const char *name, CassUuid value);
  void bind(size_t index, CassInet value);
  void bind_by_name(const char *name, CassInet value);

  friend void swap(CsandraStatement &lhs, CsandraStatement &rhs) noexcept;

private:
  CassStatement *m_inner;
};

class CsandraCluster
{
public:
  static CsandraCluster make();

  CsandraCluster() noexcept = default;
  explicit CsandraCluster(CassCluster *inner) noexcept;
  ~CsandraCluster() noexcept;
  CsandraCluster(CsandraCluster &&other) noexcept;
  CsandraCluster &operator=(CsandraCluster &&other) noexcept;

  // This is a non-copy type in order to prevent double freeing.
  CsandraCluster(const CsandraCluster &) = delete;
  CsandraCluster &operator=(const CsandraCluster &) = delete;

  explicit operator bool() const noexcept;

  CassCluster *inner() noexcept;
  const CassCluster *inner() const noexcept;

  void set_contact_points(const char *contact_points);

  friend void swap(CsandraCluster &lhs, CsandraCluster &rhs) noexcept;

private:
  CassCluster *m_inner;
};

class CsandraFuture
{
public:
  CsandraFuture() noexcept = default;
  explicit CsandraFuture(CassFuture *inner) noexcept;
  ~CsandraFuture() noexcept;
  CsandraFuture(CsandraFuture &&other) noexcept;
  CsandraFuture &operator=(CsandraFuture &&other) noexcept;

  // This is a non-copy type in order to prevent double freeing.
  CsandraFuture(const CsandraFuture &) = delete;
  CsandraFuture &operator=(const CsandraFuture &) = delete;

  explicit operator bool() const noexcept;

  CassFuture *inner() noexcept;
  const CassFuture *inner() const noexcept;

  // TODO (haslersn): implement cass_future_set_callback
  bool ready() const;
  void wait() const;
  bool wait_timed(std::chrono::microseconds timeout) const;
  CsandraResult get_result() const;
  // TODO (haslersn): implement cass_future_get_error_result
  // TODO (haslersn): implement cass_future_get_prepared
  CassError error_code() const;
  const char *error_message() const;
  CassUuid tracing_id() const;
  size_t custom_payload_item_count() const;
  // TODO (haslersn): implement cass_future_custom_payload_item

  friend void swap(CsandraFuture &lhs, CsandraFuture &rhs) noexcept;

private:
  CassFuture *m_inner;
};

class CsandraSession
{
public:
  static CsandraSession make();

  CsandraSession() noexcept = default;
  explicit CsandraSession(CassSession *inner) noexcept;
  ~CsandraSession() noexcept;
  CsandraSession(CsandraSession &&other) noexcept;
  CsandraSession &operator=(CsandraSession &&other) noexcept;

  // This is a non-copy type in order to prevent double freeing.
  CsandraSession(const CsandraSession &) = delete;
  CsandraSession &operator=(const CsandraSession &) = delete;

  explicit operator bool() const noexcept;

  CassSession *inner() noexcept;
  const CassSession *inner() const noexcept;

  CsandraFuture connect(const CsandraCluster &cluster);
  CsandraFuture connect_keyspace(const CsandraCluster &cluster, const char *keyspace);
  CsandraFuture close();
  CsandraFuture prepare(const char *query);
  CsandraFuture prepare_from_existing(CsandraStatement &statement);
  CsandraFuture execute(const CsandraStatement &statement);
  // TODO (haslersn): implement cass_session_execute_batch
  // TODO (haslersn): implement cass_session_get_schema_meta
  // TODO (haslersn): implement cass_session_get_metrics
  // TODO (haslersn): implement cass_session_get_speculative_execution_metrics
  CassUuid get_client_id() const;

  friend void swap(CsandraSession &lhs, CsandraSession &rhs) noexcept;

private:
  CassSession *m_inner;
};

#endif // CSANDRA_HPP_
