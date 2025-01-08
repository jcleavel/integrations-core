# (C) Datadog, Inc. 2024-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
from datadog_checks.base.checks.openmetrics.v2.metrics import DEFAULT_GO_METRICS

# https://argo-cd.readthedocs.io/en/stable/operator-manual/metrics/
PRIVELEGED_METRICS = {
    'auth_users_user_count': 'auth_users.user_count',
    'db_sql_connection_closed_max_idle_time': 'db.sql.connection_closed_max_idle_time',
    'db_sql_connection_closed_max_idle': 'db.sql.connection_closed_max_idle',
    'db_sql_connection_closed_max_lifetime': 'db.sql.connection_closed_max_lifetime',
    'db_sql_connection_max_open': 'db.sql.connection_max_open',
    'db_sql_connection_open': 'db.sql.connection_open',
    'db_sql_connection_wait_duration_milliseconds': 'db.sql.connection_wait_duration',
    'db_sql_connection_wait': 'db.sql.connection_wait',
    'db_transmit_bytes': 'db.transmit_bytes',
    'go_memstats_last_gc_time_seconds': {
        'name': 'go.memstats.last_gc_time.seconds',
        'type': 'time_elapsed',
    },
    'http_server_duration_milliseconds': 'http.server.duration',
    'http_server_request_size_bytes': 'http.server.request.size_bytes',
    'http_server_response_size_bytes': 'http.server.response.size_bytes',
    'http_status_codes': 'http.status_codes',
    'node_cpu_guest_seconds': 'node.cpu.guest_seconds',
    'node_cpu_seconds': 'node.cpu.seconds',
    'node_disk_discard_time_seconds': 'node.disk.discard_time_seconds',
    'node_disk_discarded_sectors': 'node.disk.discarded_sectors',
    'node_disk_discards_completed': 'node.disk.discards_completed',
    'node_disk_discards_merged': 'node.disk.discards_merged',
    'node_disk_flush_requests_time_seconds': 'node.disk.flush_requests_time_seconds',
    'node_disk_flush_requests': 'node.disk.flush_requests',
    'node_disk_io_now': 'node.disk.io_now',
    'node_disk_io_time_seconds': 'node.disk.io_time_seconds',
    'node_disk_io_time_weighted_seconds': 'node.disk.io_time_weighted_seconds',
    'node_disk_read_bytes': 'node.disk.read_bytes',
    'node_disk_read_time_seconds': 'node.disk.read_time_seconds',
    'node_disk_reads_completed': 'node.disk.reads_completed',
    'node_disk_reads_merged': 'node.disk.reads_merged',
    'node_disk_write_time_seconds': 'node.disk.write_time_seconds',
    'node_disk_writes_completed': 'node.disk.writes_completed',
    'node_disk_writes_merged': 'node.disk.writes_merged',
    'node_disk_written_bytes': 'node.disk.written_bytes',
    'node_filesystem_avail_bytes': 'node.filesystem.available_bytes',
    'node_filesystem_device_error': 'node.filesystem.device_error',
    'node_filesystem_files': 'node.filesystem.files',
    'node_filesystem_files_free': 'node.filesystem.files_free',
    'node_filesystem_free_bytes': 'node.filesystem.free_bytes',
    'node_filesystem_readonly': 'node.filesystem.readonly',
    'node_filesystem_size_bytes': 'node.filesystem.size_bytes',
    'node_load1': 'node.load1',
    'node_load15': 'node.load15',
    'node_load5': 'node.load5',
    'node_memory_Active_anon_bytes': 'node.memory.active_anon_bytes',
    'node_memory_Active_bytes': 'node.memory.active_bytes',
    'node_memory_Active_file_bytes': 'node.memory.active_file_bytes',
    'node_memory_AnonHugePages_bytes': 'node.memory.anon_huge_pages_bytes',
    'node_memory_AnonPages_bytes': 'node.memory.anon_pages_bytes',
    'node_memory_Bounce_bytes': 'node.memory.bounce_bytes',
    'node_memory_Buffers_bytes': 'node.memory.buffers_bytes',
    'node_memory_Cached_bytes': 'node.memory.cached_bytes',
    'node_memory_CommitLimit_bytes': 'node.memory.commit_limit_bytes',
    'node_memory_Committed_AS_bytes': 'node.memory.committed_as_bytes',
    'node_memory_Dirty_bytes': 'node.memory.dirty_bytes',
    'node_memory_FileHugePages_bytes': 'node.memory.file_huge_pages_bytes',
    'node_memory_FilePmdMapped_bytes': 'node.memory.file_pmd_mapped_bytes',
    'node_memory_HardwareCorrupted_bytes': 'node.memory.hardware_corrupted_bytes',
    'node_memory_HugePages_Free': 'node.memory.huge_pages_free',
    'node_memory_HugePages_Rsvd': 'node.memory.huge_pages_reserved',
    'node_memory_HugePages_Surp': 'node.memory.huge_pages_surp',
    'node_memory_HugePages_Total': 'node.memory.huge_pages_total',
    'node_memory_Hugepagesize_bytes': 'node.memory.huge_page_size_bytes',
    'node_memory_Hugetlb_bytes': 'node.memory.hugetlb_bytes',
    'node_memory_Inactive_anon_bytes': 'node.memory.inactive_anon_bytes',
    'node_memory_Inactive_bytes': 'node.memory.inactive_bytes',
    'node_memory_Inactive_file_bytes': 'node.memory.inactive_file_bytes',
    'node_memory_KReclaimable_bytes': 'node.memory.kreclaimable_bytes',
    'node_memory_KernelStack_bytes': 'node.memory.kernel_stack_bytes',
    'node_memory_Mapped_bytes': 'node.memory.mapped_bytes',
    'node_memory_MemAvailable_bytes': 'node.memory.mem_available_bytes',
    'node_memory_MemFree_bytes': 'node.memory.mem_free_bytes',
    'node_memory_MemTotal_bytes': 'node.memory.mem_total_bytes',
    'node_memory_Mlocked_bytes': 'node.memory.mlocked_bytes',
    'node_memory_NFS_Unstable_bytes': 'node.memory.nfs_unstable_bytes',
    'node_memory_PageTables_bytes': 'node.memory.page_tables_bytes',
    'node_memory_Percpu_bytes': 'node.memory.percpu_bytes',
    'node_memory_SReclaimable_bytes': 'node.memory.sreclaimable_bytes',
    'node_memory_SUnreclaim_bytes': 'node.memory.sunreclaim_bytes',
    'node_memory_ShmemHugePages_bytes': 'node.memory.shmem_huge_pages_bytes',
    'node_memory_ShmemPmdMapped_bytes': 'node.memory.shmem_pmd_mapped_bytes',
    'node_memory_Shmem_bytes': 'node.memory.shmem_bytes',
    'node_memory_Slab_bytes': 'node.memory.slab_bytes',
    'node_memory_SwapCached_bytes': 'node.memory.swap_cached_bytes',
    'node_memory_SwapFree_bytes': 'node.memory.swap_free_bytes',
    'node_memory_SwapTotal_bytes': 'node.memory.swap_total_bytes',
    'node_memory_Unevictable_bytes': 'node.memory.unevictable_bytes',
    'node_memory_VmallocChunk_bytes': 'node.memory.vm_alloc_chunk_bytes',
    'node_memory_VmallocTotal_bytes': 'node.memory.vm_alloc_total_bytes',
    'node_memory_VmallocUsed_bytes': 'node.memory.vm_alloc_used_bytes',
    'node_memory_WritebackTmp_bytes': 'node.memory.writeback_tmp_bytes',
    'node_memory_Writeback_bytes': 'node.memory.writeback_bytes',
    'node_network_receive_bytes': 'node.network.receive_bytes',
    'node_network_receive_compressed': 'node.network.receive_compressed',
    'node_network_receive_drop': 'node.network.receive_drop',
    'node_network_receive_errs': 'node.network.receive_errors',
    'node_network_receive_fifo': 'node.network.receive_fifo',
    'node_network_receive_frame': 'node.network.receive_frame',
    'node_network_receive_multicast': 'node.network.receive_multicast',
    'node_network_receive_packets': 'node.network.receive_packets',
    'node_network_transmit_bytes': 'node.network.transmit_bytes',
    'node_network_transmit_carrier': 'node.network.transmit_carrier',
    'node_network_transmit_colls': 'node.network.transmit_colls',
    'node_network_transmit_compressed': 'node.network.transmit_compressed',
    'node_network_transmit_drop': 'node.network.transmit_drop',
    'node_network_transmit_errs': 'node.network.transmit_errors',
    'node_network_transmit_fifo': 'node.network.transmit_fifo',
    'node_network_transmit_packets': 'node.network.transmit_packets',
    'node_scrape_collector_duration_seconds': 'node.scrape.collector_duration_seconds',
    'node_scrape_collector_success': 'node.scrape.collector_success',
    # We force type since node.vmstat.* metrics are untyped
    'node_vmstat_oom_kill': {
        'name': 'node.vmstat.oom_kill',
        'type': 'counter',
    },
    'node_vmstat_pgfault': {
        'name': 'node.vmstat.pgfault',
        'type': 'counter',
    },
    'node_vmstat_pgmajfault': {
        'name': 'node.vmstat.pgmajfault',
        'type': 'counter',
    },
    'node_vmstat_pgpgin': {
        'name': 'node.vmstat.pgpgin',
        'type': 'counter',
    },
    'node_vmstat_pgpgout': {
        'name': 'node.vmstat.pgpgout',
        'type': 'counter',
    },
    'node_vmstat_pswpin': {
        'name': 'node.vmstat.pswpin',
        'type': 'counter',
    },
    'node_vmstat_pswpout': {
        'name': 'node.vmstat.pswpout',
        'type': 'counter',
    },
    'pg_database_size_bytes': 'pg_database_size.bytes',
    'pg_database_size_mb': 'pg_database_size.mb',
    'pg_exporter_last_scrape_duration_seconds': 'pg_exporter.last_scrape_duration_seconds',
    'pg_exporter_last_scrape_error': 'pg_exporter.last_scrape_error',
    'pg_exporter_scrapes': 'pg_exporter.scrapes',
    'pg_exporter_user_queries_load_error': 'pg_exporter.user_queries_load_error',
    'pg_ls_archive_statusdir_wal_pending_count': 'pg_ls.archive_statusdir_wal_pending_count',
    'pg_scrape_collector_duration_seconds': 'pg_scrape_collector.duration_seconds',
    'pg_scrape_collector_success': 'pg_scrape_collector.success',
    'pg_settings_default_transaction_read_only': 'pg_settings.default_transaction_read_only',
    'pg_stat_activity_xact_runtime': 'pg_stat_activity.xact_runtime',
    'pg_stat_bgwriter_buffers_alloc': 'pg_stat_bgwriter.buffers_alloc',
    'pg_stat_bgwriter_buffers_backend_fsync': 'pg_stat_bgwriter.buffers_backend_fsync',
    'pg_stat_bgwriter_buffers_backend': 'pg_stat_bgwriter.buffers_backend',
    'pg_stat_bgwriter_buffers_checkpoint': 'pg_stat_bgwriter.buffers_checkpoint',
    'pg_stat_bgwriter_buffers_clean': 'pg_stat_bgwriter.buffers_clean',
    'pg_stat_bgwriter_checkpoint_sync_time': 'pg_stat_bgwriter.checkpoint_sync_time',
    'pg_stat_bgwriter_checkpoint_write_time': 'pg_stat_bgwriter.checkpoint_write_time',
    'pg_stat_bgwriter_checkpoints_req': 'pg_stat_bgwriter.checkpoints_req',
    'pg_stat_bgwriter_checkpoints_timed': 'pg_stat_bgwriter.checkpoints_timed',
    'pg_stat_bgwriter_maxwritten_clean': 'pg_stat_bgwriter.maxwritten_clean',
    'pg_stat_bgwriter_stats_reset': 'pg_stat_bgwriter.stats_reset',
    'pg_stat_database_blks_hit': 'pg_stat_database.blks_hit',
    'pg_stat_database_blks_read': 'pg_stat_database.blks_read',
    'pg_stat_database_conflicts_confl_bufferpin': 'pg_stat_database_conflicts.confl_bufferpin',
    'pg_stat_database_conflicts_confl_deadlock': 'pg_stat_database_conflicts.confl_deadlock',
    'pg_stat_database_conflicts_confl_lock': 'pg_stat_database_conflicts.confl_lock',
    'pg_stat_database_conflicts_confl_snapshot': 'pg_stat_database_conflicts.confl_snapshot',
    'pg_stat_database_conflicts_confl_tablespace': 'pg_stat_database_conflicts.confl_tablespace',
    'pg_stat_database_conflicts': 'pg_stat_database.conflicts',
    'pg_stat_database_deadlocks': 'pg_stat_database.deadlocks',
    'pg_stat_database_most_recent_reset': 'pg_stat_database.most_recent_reset',
    'pg_stat_database_num_backends': 'pg_stat_database.num_backends',
    'pg_stat_database_temp_bytes': 'pg_stat_database.temp_bytes',
    'pg_stat_database_temp_files': 'pg_stat_database.temp_files',
    'pg_stat_database_tup_deleted': 'pg_stat_database.tup_deleted',
    'pg_stat_database_tup_fetched': 'pg_stat_database.tup_fetched',
    'pg_stat_database_tup_inserted': 'pg_stat_database.tup_inserted',
    'pg_stat_database_tup_returned': 'pg_stat_database.tup_returned',
    'pg_stat_database_tup_updated': 'pg_stat_database.tup_updated',
    'pg_stat_database_xact_commit': 'pg_stat_database.xact_commit',
    'pg_stat_database_xact_rollback': 'pg_stat_database.xact_rollback',
    'pg_stat_replication_replay_lag': 'pg_stat_replication.replay_lag',
    'pg_stat_replication_send_lag': 'pg_stat_replication.send_lag',
    'pg_stat_statements_total_queries': 'pg_stat_statements.total_queries',
    'pg_stat_statements_total_time_seconds': 'pg_stat_statements.total_time_seconds',
    'pg_status_in_recovery': 'pg_status.in_recovery',
    'pg_up': 'pg.up',
    'pg_wal_size_mb': 'pg_wal.size',
    'pgrst_db_pool_available': 'pgrst.db_pool.available_connections',
    'pgrst_db_pool_max': 'pgrst.db_pool.max_connections',
    'pgrst_db_pool_timeouts': 'pgrst.db_pool.connection_timeouts',
    'pgrst_db_pool_waiting': 'pgrst.db_pool.requests_waiting',
    'pgrst_schema_cache_loads': 'pgrst.schema_cache.loads',
    'pgrst_schema_cache_query_time_seconds': 'pgrst.schema_cache.query_time_seconds',
    'physical_replication_lag_is_connected_to_primary': 'physical_replication_lag.is_connected_to_primary',
    'physical_replication_lag_is_wal_replay_paused': 'physical_replication_lag.is_wal_replay_paused',
    'physical_replication_lag_physical_replication_lag_seconds': 'physical_replication_lag.seconds',
    'postgres_exporter_build_info': 'postgres_exporter.build_info',
    'postgres_exporter_config_last_reload_success_timestamp_seconds': 'postgres_exporter.config_last_reload_success_timestamp_seconds',  # noqa: E501
    'postgres_exporter_config_last_reload_successful': 'postgres_exporter.config_last_reload_successful',
    'postgresql_restarts': 'postgresql.restarts',
    'process_start_time_seconds': {
        'name': 'process.start_time.seconds',
        'type': 'time_elapsed',
    },
    'process_runtime_go_mem_live_objects': 'process.runtime.go_mem_live_objects',
    'promhttp_metric_handler_requests_in_flight': 'promhttp_metric_handler.requests_in_flight',
    'promhttp_metric_handler_requests': 'promhttp_metric_handler.requests',
    'realtime_postgres_changes_client_subscriptions': 'realtime_postgres_changes.client_subscriptions',
    'realtime_postgres_changes_total_subscriptions': 'realtime_postgres_changes.total_subscriptions',
    'replication_slots_max_lag_bytes': 'pg_replication_slots.max_lag_bytes',
    'runtime_uptime_milliseconds': {'name': 'runtime.uptime_milliseconds', 'type': 'time_elapsed'},
    'storage_storage_size_mb': 'storage.storage_size',
    'supabase_usage_metrics_user_queries': 'usage_metrics.user_queries',
}

STORAGE_API_METRICS = [
    {
        'storage_api_upload_started': 'upload_started',
        'storage_api_upload_success': 'upload_success',
        'storage_api_database_query_performance': 'database_query_performance',
        'storage_api_queue_job_scheduled': 'queue.job_scheduled',
        'storage_api_queue_job_scheduled_time': 'queue.job_scheduled_time',
        'storage_api_queue_job_completed': 'queue.job_completed',
        'storage_api_queue_job_retry_failed': 'queue.job_retry_failed',
        'storage_api_queue_job_error': 'queue.job_error',
        'storage_api_s3_upload_part': 's3_upload_part',
        'storage_api_db_pool': 'db_pool',
        'storage_api_db_connections': 'db_connections',
        'storage_api_http_pool_busy_sockets': 'http_pool.busy_sockets',
        'storage_api_http_pool_free_sockets': 'http_pool.free_sockets',
        'storage_api_http_pool_requests': 'http_pool.requests',
        'storage_api_http_pool_errors': 'http_pool.errors',
        'storage_api_http_request_summary_seconds': 'http_request.summary_seconds',
        'storage_api_http_request_duration_seconds': 'http_request.duration_seconds',
        'storage_api_process_cpu_seconds': 'process_cpu.seconds',
        'storage_api_process_cpu_system_seconds': 'process_cpu.system.seconds',
        'storage_api_process_cpu_user_seconds': 'process_cpu.user.seconds',
        'storage_api_process_start_time_seconds': {
            'name': 'process.uptime.seconds',
            'type': 'time_elapsed',
        },
        'storage_api_process_resident_memory_bytes': 'process.resident_memory.bytes',
        'storage_api_process_virtual_memory_bytes': 'process.virtual_memory.bytes',
        'storage_api_process_heap_bytes': 'process.heap_bytes',
        'storage_api_process_open_fds': 'process.open_fds',
        'storage_api_process_max_fds': 'process.max_fds',
        'storage_api_nodejs_eventloop_lag_seconds': 'nodejs.eventloop_lag.seconds',
        'storage_api_nodejs_eventloop_lag_min_seconds': 'nodejs_eventloop_lag.min_seconds',
        'storage_api_nodejs_eventloop_lag_max_seconds': 'nodejs.eventloop_lag.max_seconds',
        'storage_api_nodejs_eventloop_lag_mean_seconds': 'nodejs.eventloop_lag.mean_seconds',
        'storage_api_nodejs_eventloop_lag_stddev_seconds': 'nodejs.eventloop_lag.stddev_seconds',
        'storage_api_nodejs_eventloop_lag_p50_seconds': 'nodejs.eventloop_lag.p50_seconds',
        'storage_api_nodejs_eventloop_lag_p90_seconds': 'nodejs.eventloop_lag.p90_seconds',
        'storage_api_nodejs_eventloop_lag_p99_seconds': 'nodejs.eventloop_lag.p99_seconds',
        'storage_api_nodejs_active_resources': 'nodejs.active_resources',
        'storage_api_nodejs_active_resources_total': 'nodejs.active_resources.total',
        'storage_api_nodejs_active_handles': 'nodejs.active_handles',
        'storage_api_nodejs_active_handles_total': 'nodejs.active_handles.total',
        'storage_api_nodejs_active_requests': 'nodejs.active_requests',
        'storage_api_nodejs_active_requests_total': 'nodejs.active_requests.total',
        'storage_api_nodejs_gc_duration_seconds': 'nodejs.gc_duration.seconds',
        'storage_api_nodejs_heap_size_total_bytes': 'nodejs.heap_size.total_bytes',
        'storage_api_nodejs_heap_size_used_bytes': 'nodejs.heap_size.used_bytes',
        'storage_api_nodejs_external_memory_bytes': 'nodejs.external_memory.bytes',
        'storage_api_nodejs_heap_space_size_total_bytes': 'nodejs.heap_space_size.total_bytes',
        'storage_api_nodejs_heap_space_size_used_bytes': 'nodejs.heap_space_size.used_bytes',
        'storage_api_nodejs_heap_space_size_available_bytes': 'nodejs.heap_space_size.available_bytes',
        'storage_api_nodejs_version_info': 'nodejs.version_info',
    }
]

RENAME_LABELS_MAP = {
    'version': 'component_version',
}

SUPABASE_METRICS = [{**DEFAULT_GO_METRICS, **PRIVELEGED_METRICS}]