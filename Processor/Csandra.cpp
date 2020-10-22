#include "Processor/Csandra.hpp"

#include <cassert>
#include <stdexcept>

// CsandraError

CsandraError::CsandraError(CassError error_code, const std::string &what_arg)
    : std::runtime_error(what_arg), m_error_code(error_code)
{
}

CsandraError::CsandraError(CassError error_code, const char *what_arg)
    : std::runtime_error(what_arg), m_error_code(error_code)
{
}

CassError CsandraError::error_code() const noexcept { return m_error_code; }

// CsandraResult

CsandraResult::CsandraResult(const CassResult *inner) noexcept : m_inner(inner) {}

CsandraResult::~CsandraResult() noexcept
{
  if (m_inner != nullptr) {
    cass_result_free(m_inner);
  }
}

CsandraResult::CsandraResult(CsandraResult &&other) noexcept
{
  m_inner = other.m_inner;
  other.m_inner = nullptr;
}

CsandraResult &CsandraResult::operator=(CsandraResult &&other) noexcept
{
  CsandraResult temp{std::move(other)};
  swap(*this, temp);
  return *this;
}

CsandraResult::operator bool() const noexcept { return m_inner != nullptr; }

const CassResult *CsandraResult::inner() const noexcept { return m_inner; }

void swap(CsandraResult &lhs, CsandraResult &rhs) noexcept { std::swap(lhs.m_inner, rhs.m_inner); }

// CsandraStatement

CsandraStatement CsandraStatement::make(const char *query, size_t parameter_count)
{
  CsandraStatement result{cass_statement_new(query, parameter_count)};
  if (result.inner() == nullptr) {
    throw std::runtime_error{"Failed to allocate new CassStatement."};
  }
  return result;
}

CsandraStatement::CsandraStatement(CassStatement *inner) noexcept : m_inner(inner) {}

CsandraStatement::~CsandraStatement() noexcept
{
  if (m_inner != nullptr) {
    cass_statement_free(m_inner);
  }
}

CsandraStatement::CsandraStatement(CsandraStatement &&other) noexcept
{
  m_inner = other.m_inner;
  other.m_inner = nullptr;
}

CsandraStatement &CsandraStatement::operator=(CsandraStatement &&other) noexcept
{
  CsandraStatement temp{std::move(other)};
  swap(*this, temp);
  return *this;
}

CsandraStatement::operator bool() const noexcept { return m_inner != nullptr; }

CassStatement *CsandraStatement::inner() noexcept { return m_inner; }
const CassStatement *CsandraStatement::inner() const noexcept { return m_inner; }

void CsandraStatement::reset_parameters(size_t count)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `reset_parameters` on an empty CsandraStatement."};
  }
  auto err = cass_statement_reset_parameters(m_inner, count);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`reset_parameters` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::add_key_index(size_t index)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `add_key_index` on an empty CsandraStatement."};
  }
  auto err = cass_statement_add_key_index(m_inner, index);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`add_key_index` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::set_keyspace(const char *keyspace)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `set_keyspace` on an empty CsandraStatement."};
  }
  auto err = cass_statement_set_keyspace(m_inner, keyspace);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`set_keyspace` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::set_consistency(CassConsistency consistency)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `set_consistency` on an empty CsandraStatement."};
  }
  auto err = cass_statement_set_consistency(m_inner, consistency);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`set_consistency` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::set_serial_consistency(CassConsistency serial_consistency)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `set_serial_consistency` on an empty CsandraStatement."};
  }
  auto err = cass_statement_set_serial_consistency(m_inner, serial_consistency);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`set_serial_consistency` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, nullptr_t)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_null(m_inner, index);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, nullptr_t)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_null_by_name(m_inner, name);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, int8_t value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_int8(m_inner, index, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, int8_t value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_int8_by_name(m_inner, name, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, int16_t value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_int16(m_inner, index, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, int16_t value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_int16_by_name(m_inner, name, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, int32_t value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_int32(m_inner, index, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, int32_t value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_int32_by_name(m_inner, name, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, uint32_t value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_uint32(m_inner, index, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, uint32_t value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_uint32_by_name(m_inner, name, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, int64_t value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_int64(m_inner, index, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, int64_t value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_int64_by_name(m_inner, name, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, float value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_float(m_inner, index, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, float value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_float_by_name(m_inner, name, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, double value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_double(m_inner, index, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, double value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_double_by_name(m_inner, name, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, bool value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_bool(m_inner, index, value ? cass_true : cass_false);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, bool value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_bool_by_name(m_inner, name, value ? cass_true : cass_false);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, const char *value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_string(m_inner, index, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, const char *value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_string_by_name(m_inner, name, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, boost::beast::span<uint8_t> value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_bytes(m_inner, index, value.data(), value.size());
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, boost::beast::span<uint8_t> value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_bytes_by_name(m_inner, name, value.data(), value.size());
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, CassUuid value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_uuid(m_inner, index, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, CassUuid value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_uuid_by_name(m_inner, name, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void CsandraStatement::bind(size_t index, CassInet value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_inet(m_inner, index, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind` returned error code "} + std::to_string(err) + "."};
  }
}

void CsandraStatement::bind_by_name(const char *name, CassInet value)
{
  if (m_inner == nullptr) {
    throw std::runtime_error{"Called `bind_by_name` on an empty CsandraStatement."};
  }
  auto err = cass_statement_bind_inet_by_name(m_inner, name, value);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`bind_by_name` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void swap(CsandraStatement &lhs, CsandraStatement &rhs) noexcept
{
  std::swap(lhs.m_inner, rhs.m_inner);
}

// CsandraCluster

CsandraCluster CsandraCluster::make()
{
  CsandraCluster result{cass_cluster_new()};
  if (result.inner() == nullptr) {
    throw std::runtime_error{"Failed to allocate new CassCluster."};
  }
  return result;
}

CsandraCluster::CsandraCluster(CassCluster *inner) noexcept : m_inner(inner) {}

CsandraCluster::~CsandraCluster() noexcept
{
  if (m_inner != nullptr) {
    cass_cluster_free(m_inner);
  }
}

CsandraCluster::CsandraCluster(CsandraCluster &&other) noexcept
{
  m_inner = other.m_inner;
  other.m_inner = nullptr;
}

CsandraCluster &CsandraCluster::operator=(CsandraCluster &&other) noexcept
{
  CsandraCluster temp{std::move(other)};
  swap(*this, temp);
  return *this;
}

CsandraCluster::operator bool() const noexcept { return m_inner != nullptr; }

CassCluster *CsandraCluster::inner() noexcept { return m_inner; }
const CassCluster *CsandraCluster::inner() const noexcept { return m_inner; }

void CsandraCluster::set_contact_points(const char *contact_points)
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `set_contact_points` on an empty CsandraCluster."};
  }
  auto err = cass_cluster_set_contact_points(m_inner, contact_points);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`cass_cluster_set_contact_points` returned error code "} +
                                std::to_string(err) + "."};
  }
}

void swap(CsandraCluster &lhs, CsandraCluster &rhs) noexcept
{
  std::swap(lhs.m_inner, rhs.m_inner);
}

// CsandraFuture

CsandraFuture::CsandraFuture(CassFuture *inner) noexcept : m_inner(inner) {}

CsandraFuture::~CsandraFuture() noexcept
{
  if (m_inner != nullptr) {
    cass_future_free(m_inner);
  }
}

CsandraFuture::CsandraFuture(CsandraFuture &&other) noexcept
{
  m_inner = other.m_inner;
  other.m_inner = nullptr;
}

CsandraFuture &CsandraFuture::operator=(CsandraFuture &&other) noexcept
{
  CsandraFuture temp{std::move(other)};
  swap(*this, temp);
  return *this;
}

CsandraFuture::operator bool() const noexcept { return m_inner != nullptr; }

CassFuture *CsandraFuture::inner() noexcept { return m_inner; }
const CassFuture *CsandraFuture::inner() const noexcept { return m_inner; }

bool CsandraFuture::ready() const
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `ready` on an empty CsandraFuture."};
  }
  return cass_future_ready(m_inner) == cass_true;
}

void CsandraFuture::wait() const
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `wait` on an empty CsandraFuture."};
  }
  cass_future_wait(m_inner);
}

bool CsandraFuture::wait_timed(std::chrono::microseconds timeout) const
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `wait_timed` on an empty CsandraFuture."};
  }
  return cass_future_wait_timed(m_inner, static_cast<cass_duration_t>(timeout.count())) ==
         cass_true;
}

CsandraResult CsandraFuture::get_result() const
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `get_result` on an empty CsandraFuture."};
  }
  auto err = cass_future_error_code(m_inner);
  if (err != CASS_OK) {
    const char *message;
    size_t message_length;
    cass_future_error_message(m_inner, &message, &message_length);
    throw CsandraError{err, message};
  }
  return CsandraResult{cass_future_get_result(m_inner)};
}

CassError CsandraFuture::error_code() const
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `error_code` on an empty CsandraFuture."};
  }
  return cass_future_error_code(m_inner);
}

const char *CsandraFuture::error_message() const
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `error_message` on an empty CsandraFuture."};
  }
  const char *message;
  size_t message_length;
  cass_future_error_message(m_inner, &message, &message_length);
  return message;
}

CassUuid CsandraFuture::tracing_id() const
{
  CassUuid result;
  auto err = cass_future_tracing_id(m_inner, &result);
  if (err != CASS_OK) {
    throw CsandraError{err, std::string{"`cass_future_tracing_id` returned error code "} +
                                std::to_string(err) + "."};
  }
  return result;
}

size_t CsandraFuture::custom_payload_item_count() const
{
  return cass_future_custom_payload_item_count(m_inner);
}

void swap(CsandraFuture &lhs, CsandraFuture &rhs) noexcept { std::swap(lhs.m_inner, rhs.m_inner); }

// CsandraSession

CsandraSession CsandraSession::make()
{
  CsandraSession result{cass_session_new()};
  if (result.inner() == nullptr) {
    throw std::runtime_error{"Failed to allocate new CassSession."};
  }
  return result;
}

CsandraSession::CsandraSession(CassSession *inner) noexcept : m_inner(inner) {}

CsandraSession::~CsandraSession() noexcept
{
  if (m_inner != nullptr) {
    cass_session_free(m_inner);
  }
}

CsandraSession::CsandraSession(CsandraSession &&other) noexcept
{
  m_inner = other.m_inner;
  other.m_inner = nullptr;
}

CsandraSession &CsandraSession::operator=(CsandraSession &&other) noexcept
{
  CsandraSession temp{std::move(other)};
  swap(*this, temp);
  return *this;
}

CsandraSession::operator bool() const noexcept { return m_inner != nullptr; }

CassSession *CsandraSession::inner() noexcept { return m_inner; }
const CassSession *CsandraSession::inner() const noexcept { return m_inner; }

CsandraFuture CsandraSession::connect(const CsandraCluster &cluster)
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `connect` on an empty CsandraSession."};
  }
  return CsandraFuture{cass_session_connect(m_inner, cluster.inner())};
}

CsandraFuture CsandraSession::connect_keyspace(const CsandraCluster &cluster, const char *keyspace)
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `connect_keyspace` on an empty CsandraSession."};
  }
  return CsandraFuture{cass_session_connect_keyspace(m_inner, cluster.inner(), keyspace)};
}

CsandraFuture CsandraSession::close()
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `close` on an empty CsandraSession."};
  }
  return CsandraFuture{cass_session_close(m_inner)};
}

CsandraFuture CsandraSession::prepare(const char *query)
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `prepare` on an empty CsandraSession."};
  }
  return CsandraFuture{cass_session_prepare(m_inner, query)};
}

CsandraFuture CsandraSession::prepare_from_existing(CsandraStatement &statement)
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `prepare_from_existing` on an empty CsandraSession."};
  }
  return CsandraFuture{cass_session_prepare_from_existing(m_inner, statement.inner())};
}

CsandraFuture CsandraSession::execute(const CsandraStatement &statement)
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `execute` on an empty CsandraSession."};
  }
  return CsandraFuture{cass_session_execute(m_inner, statement.inner())};
}

CassUuid CsandraSession::get_client_id() const
{
  if (m_inner == nullptr) {
    throw std::logic_error{"Called `get_client_id` on an empty CsandraSession."};
  }
  return cass_session_get_client_id(m_inner);
}

void swap(CsandraSession &lhs, CsandraSession &rhs) noexcept
{
  std::swap(lhs.m_inner, rhs.m_inner);
}
